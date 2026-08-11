# Design 10: Agent Executor (AX) — standing evaluation

**Status:** 🔍 Standing evaluation · **Verdict: do not adopt yet** · **Reviewed 2026-08-11 · next review
2026-11**

> **Not a specification.** Every other document in this directory describes the end state we are
> building toward. This one answers a recurring question — "should we adopt
> [google/ax](https://github.com/google/ax) yet?" — with a dated verdict and the conditions that
> would change it. It decides nothing about kube-agents' own architecture. When the verdict flips,
> the design work that follows belongs in a new document, not in this one.

**Overview:** [README.md](README.md) · **Depends on:** [09](09-runner-contract.md),
[08](08-agent-runtime-and-identity.md) · **Tier:** Evaluation

---

## TL;DR

AX is a distributed agent runtime that gives an agent run **durability**: an event log, snapshots,
and suspend/resume across pods. That is a real hole in kube-agents — a run today dies with its pod
and is redone from nothing, and the recovery that saves us from worse is an 838-line patch against
Hermes's scheduler that we maintain ourselves (§2) — and AX is aimed squarely at it.

We are not adopting it yet, for four reasons that are about calendar rather than merit: it is four
months old and pre-1.0, its own README pauses external contributions for "a significant
architectural redesign", its recommended production deployment is a second pre-1.0 project at
`v0.0.0`, and the one feature that would matter most to our security model — tool-call approvals —
is on its roadmap rather than in it.

The trigger conditions in §5 are written to be checked, not argued about. Four of the five are
theirs; the fifth — a real Hermes runner passing our own conformance suite — is ours, and until it
lands there is nothing to port and no baseline to port it against.

---

## 1. What AX is, as of 2026-08-11

Facts, with the date they were read, because this document exists to be re-read against a moving
target. Everything here comes from the repository and its README, not from coverage of it.

|                  |                                                                                                                |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| Repository       | [github.com/google/ax](https://github.com/google/ax), Apache-2.0, Go                                           |
| First commit     | 2026-03-30 — roughly four months old                                                                           |
| Latest release   | `v0.2.2`, 2026-07-23 (four releases total; `v0.1.0` was 2026-05-20)                                            |
| Self-description | "An open source distributed agent runtime"                                                                     |
| Stated status    | "**AX is in active early development.** … major breaking changes prior to a stable release"                    |
| Contributions    | "We are temporarily pausing the acceptance of external Pull Requests while we stabilize the core architecture" |

**What it does.** AX runs agents as durable, resumable, isolated executions. Its components are an
AX Server (multi-tenant), an event log store, an actor controller that owns compute, and a harness
server that holds the session. Durability is the through-line: the event log is what a resumed run
replays, and single-writer semantics are what keep the replay consistent.

**What a harness is.** AX's plug-in point. A harness implements `HarnessService` and supplies the
agentic behaviour; AX supplies the envelope around it. One ships in the box — **Antigravity**,
which targets Gemini through Google AI Studio or Vertex AI.

**How a run is triggered.** Three ways: the `ax` CLI, `ax serve` as a gRPC server, or Kubernetes,
where AX's recommended production deployment is on **Agent Substrate**.

**What AX says it is not:** a managed service, and an agent framework. Both disclaimers are useful
to us — the first because we would self-host it, the second because it means AX does not compete
with Hermes or with our skills.

## 2. What it would replace: the durability hole under the runner contract

[09](09-runner-contract.md) draws the line between the control plane (what decides a run should
happen) and the execution plane (what runs the turn). AX is an execution-plane candidate. It would
not replace the contract; it would sit under one.

**The hole is real, and it is worth stating precisely, because the obvious overstatement of it is
false.** kube-agents has no run durability: a run holds its state in the process, so a pod restart,
a node drain, or an image upgrade destroys it, and nothing resumes it.

What the fleet does have is _recovery_, which is a different thing.
`deploy/docker/patches/kanban_scheduling.py` sweeps `running` cards whose recorded worker PID is
gone back to `ready` (`release_dead_foreign_claims`), and behind that sit upstream's 900-second
claim TTL and the `--max-runtime` the dispatcher stamps on every card it files
(`platform_cron_dispatch.py:521`). A fleet audit killed twenty minutes in is therefore
re-dispatched, not stranded; the schedule recovers without a person in the loop.

Two things follow, and both are arguments for AX rather than against it. First, **recovery is not
resumption.** The re-dispatched run starts from nothing, so a long audit pays for itself twice, and
the tick it was filling is skipped while the card is still in flight — the dispatcher counts
`ready` and `running` alike as `IN_FLIGHT` (line 132). Second, and more to the point of this
document, **that recovery machinery is ours.** It is an 838-line build-time patch against Hermes's
scheduler, written after a specific incident and carrying that incident in its module docstring.
AX's event log and resumption would make durability a property of the runtime instead of a patch
set we maintain — and the size of that patch set is a number this project is deliberately trying
not to grow.

Beyond durability, the other thing AX would offer is density. Our model is one long-lived pod per
PlatformAgent, sized for a workload that is idle most of the time; AX's actor/worker multiplexing is
designed for exactly that shape.

**What it would not replace,** and this is most of what kube-agents is: the control plane, the
credential-proxy sidecar and its three refusal gates (`executable.allowlist`, the argv policy
engine, and `git.workspace.lease`), profiles and skills, the operator and its CRD, and the kanban
board. Adopting AX is a change to _where a turn executes_, not to what the product does.

## 3. The seam question

AX has its own seam — `HarnessService` — and we have ours, [09](09-runner-contract.md)'s
`run(principal, profile, task, workspace, budget) -> events`. Adoption means deciding which sits
inside which, and there is only one answer that does not cost us the contract: **our runner
contract lives inside an AX harness**, with AX owning suspension, the event log and resumption, and
the harness owning the turn. In that arrangement 09 survives intact and AX becomes an
implementation detail of one runner among several — which is precisely the property 09 was written
to buy.

Worth noting for whoever does that work: two of the five items 09 leaves "open at v1alpha1" (§8)
are questions AX has already answered for itself. Cancellation has an inbound channel there and
none here, and its event log makes the budget-enforcement location an explicit choice rather than
an unlocated one. If we adopt, those answers arrive with it — and if we do not, they are still
worth reading before we settle §8 ourselves. Resumption is the reverse case: it is AX's central
concern and 09 does not raise it at all, which is the clearest single sign that 09 specifies a turn
and AX specifies what survives one.

## 4. What it still lacks, for us

Ordered by how hard each would be to work around.

1. **Tool-call approvals are on the roadmap, not in the product.** This is the blocker that matters.
   kube-agents' security posture is not sandbox isolation — it is the credential proxy: the agent
   container holds no credentials and reaches `gcloud`, `kubectl`, `gh` and `git` only by sending an
   argument vector to a sidecar that decides, per argv, whether the command runs
   ([`credential-isolation-design.md`](../credential-isolation-design.md) is canonical; this
   paragraph is a summary and defers to it). AX's isolation is
   environment-shaped (a sandboxed actor with its own filesystem and RAM), which is orthogonal: it
   has no notion of refusing _this_ command line. Adopting AX therefore does not let us retire the
   proxy, and until "tool call approvals from harnesses" ships there is nothing on the AX side to
   compose it with. We would be running two boundaries that do not know about each other.
2. **It authenticates the deployment, not the requester.** AX's documented auth is `GEMINI_API_KEY`
   or Application Default Credentials — one identity for the installation. 09 makes `principal`
   (subject and issuer) a required field precisely because per-user scoping and attribution are
   prerequisites here, not extras. Under AX that stays entirely our problem, carried in
   harness-level metadata AX does not interpret.
3. **No harness for the models we run.** Antigravity is Gemini and Vertex; kube-agents runs Claude
   through Hermes. We would write a `HarnessService` — which is the same work as writing a runner
   that conforms to [09](09-runner-contract.md), against an interface that is currently less stable
   than ours. AX buys us no harness.
4. **Its recommended production path is two pre-1.0 projects deep.** Agent Substrate
   ([agent-substrate/substrate](https://github.com/agent-substrate/substrate)) has exactly one
   release, `v0.0.0`, tagged 2026-05-19, and carried more than 300 open issues at the time of this
   review. Its own documentation says it is in early development, not ready for production, that its
   APIs are "almost guaranteed to change", and that it is not an officially supported Google
   product. It also brings hard requirements of its own — gVisor, Pod Certificates, its own control
   plane in Valkey/Redis rather than etcd, and a CLI (`kubectl ate`) for resources that are
   deliberately not CRDs. That is a substantial platform commitment to make on a `v0.0.0`.
5. **Stability, plainly.** Pre-1.0, four months old, breaking changes promised, and external pull
   requests closed while the core is redesigned. The last of those is the most informative: a
   project that cannot currently accept a fix from us is one we cannot currently unblock ourselves
   on.

None of these is a criticism of AX at four months old. They are reasons the calendar, not the
design, decides this.

## 5. Adoption triggers

Re-evaluate when **all five** hold. Each is written so that checking it is a lookup, not a
judgement call.

1. **AX has a stable release line.** A `v1.0.0` or later, or a published compatibility guarantee
   that survives a minor bump — and external pull requests reopened, because a dependency we cannot
   send a patch to is a dependency we cannot operate.
2. **Tool-call approvals ship, and can express an argv-level refusal** — or AX documents how a
   boundary shaped like our credential proxy composes with an actor sandbox. Failing both, we would
   be adding a runtime without being able to state where our security boundary went.
3. **A supported Kubernetes deployment exists that is not gated on a `v0.0.0`.** Either Agent
   Substrate reaches a release its own documentation calls production-ready, or AX documents a
   Kubernetes path that does not require it.
4. **A harness exists for a non-Gemini frontier model**, or `HarnessService` is stable enough that
   writing ours is a week's work rather than a rewrite each release.
5. **Hermes passes our own conformance suite** — the milestone `runner/conformance.py` calls M4.1.
   This one is ours. Until a real runner implements [09](09-runner-contract.md), there is nothing to
   port into an AX harness and no baseline to measure the port against: we would be comparing AX to
   a null runner.

Triggers 1–4 are theirs and we can only watch them. Trigger 5 is the one we control, and it is on
the roadmap independently of AX; that asymmetry is the argument for spending the next quarter on our
own seam rather than on someone else's runtime.

## 6. What we do instead, for now

Keep [09](09-runner-contract.md) and finish M4.1. The contract is what makes this decision cheap to
defer: whatever we adopt later plugs in behind an interface that already exists, and a second runner
proves that before AX is involved at all.

On the durability hole itself, do nothing further for now. The recovery path in §2 already bounds
the damage to a repeated run, and the cheaper improvements left — checkpointing an audit so a
re-dispatch resumes mid-way — are most of the work of run durability with none of the generality.
If that cost ever becomes worth paying, it is an argument for revisiting this page rather than for
building a private version of what AX already does.

## 7. Verification

- `make docs-check` — generated regions, link resolution, terminology, and this document's entry in
  the documentation map.
- **The dated facts in §1 and §4 are the point of the review**, so re-derive them rather than
  re-reading this page:

  ```bash
  # Release line, age, and activity for both projects.
  gh api repos/google/ax --jq '{created: .created_at, pushed: .pushed_at, issues: .open_issues_count}'
  gh api repos/google/ax/releases --jq 'map({tag: .tag_name, at: .published_at}) | .[0:3]'
  gh api repos/agent-substrate/substrate/releases --jq 'map(.tag_name)'

  # Trigger 1 and trigger 2: the status banner and the roadmap live in the README.
  gh api repos/google/ax/readme -H 'Accept: application/vnd.github.raw' \
    | grep -iA3 'early development\|pausing\|approval'
  ```

- A review that finds no trigger satisfied still updates §8. An empty review log entry is the
  evidence that the question was asked; silence reads the same as never having looked.

## 8. Review log

Repeat quarterly until AX is adopted or the question is closed.

| Review date | Triggers met | Verdict          | Next review |
| ----------- | ------------ | ---------------- | ----------- |
| 2026-08-11  | 0 of 5       | Do not adopt yet | 2026-11     |
