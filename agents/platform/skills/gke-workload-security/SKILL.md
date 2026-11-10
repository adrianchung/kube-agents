---
name: gke-workload-security
description: >-
  Audits, configures, and hardens workload-level security controls for Google
  Kubernetes Engine (GKE) applications and namespaces. Covers running security
  audits (`audit_cluster.sh`), enforcing Network Policies (default-deny and Dataplane
  V2 logging), isolating high-risk pods inside GKE Sandbox (`gVisor`), enforcing Pod
  Security Standards (`restricted` labeling), mounting Secret Manager secrets via
  CSI (`SecretProviderClass`), and disabling unused ServiceAccount token
  auto-mounting (`automountServiceAccountToken: false`). Use when auditing workload
  security posture, isolating namespaces, applying pod security standards, hardening
  ServiceAccount token auto-mounting, or configuring network policies and secret
  volume mounts. Don't use for Workload Identity (use gke-workload-identity), cluster-wide
  control plane security, RBAC hardening, Binary Authorization, Shielded Nodes,
  or enabling platform-level GKE add-ons (use gke-platform-security instead).
metadata:
  version: "1.0.1"
  category: Security
---

# GKE Workload Security

> **Routing Note:** For Workload Identity KSA/GSA bindings, open `gke-workload-identity/SKILL.md`. For cluster-level security flags (`--database-encryption-key`, `--security-posture`, RBAC, Shielded Nodes, Binary Authorization), open `gke-platform-security/SKILL.md`.

This skill provides workflows and best practices for securing GKE workloads. It
covers security auditing, Network Security (Network Policies), and Node Security.
For Workload Identity setup, use the `gke-workload-identity` skill.

> A change goes out as a pull request to the GitOps repository, never as a write from here: Kubernetes objects as YAML through `gke-manifest-generation`, cluster settings and other Google Cloud resources as Config Connector YAML through `gcp-config-connector`, opened with `submit-suggestion`. Each profile's config offers only the `gke` MCP server's read tools, and the broker refuses `kubectl` and `gcloud` writes.

## Workflows

### 1. Security Audit

Assess the current security posture of your cluster using the provided audit
script.

**Prerequisites:**

-   `gcloud` CLI authenticated.
-   `jq` command-line JSON processor installed.

**Capabilities:**

-   Checks for Workload Identity.
-   Verifies Network Policy is enabled.
-   Checks if Shielded Nodes are enabled.
-   Checks if Binary Authorization is enabled.
-   Checks for Private Cluster configuration.

**Command:**

```bash
/opt/data/profiles/platform/skills/gke-workload-security/scripts/audit_cluster.sh <cluster-name> <region> <project-id>
```

### 2. Configure Workload Identity (legacy GSA impersonation)

Load the `gke-workload-identity` skill first: binding IAM roles to the
Kubernetes Service Account (KSA) principal directly is the current default, and
that skill diagnoses both models. Use the impersonation setup below, where a KSA
impersonates a Google Service Account (GSA), only when a GSA must be the
identity: an existing GSA already holds the roles the workload needs, or the
Google Cloud API it calls does not accept Workload Identity Federation
principals (the GKE documentation lists those limitations).

**Steps:**

1.  **Create Namespace and annotated KSA**, proposed as a pull request through
    `submit-suggestion`:

    ```yaml
    apiVersion: v1
    kind: Namespace
    metadata:
      name: workload-identity-test-ns
    ---
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: <ksa-name>
      namespace: workload-identity-test-ns
      annotations:
        iam.gke.io/gcp-service-account: <gsa-name>@<project-id>.iam.gserviceaccount.com
    ```

2.  **Bind KSA to GSA:** grant
    `serviceAccount:<project-id>.svc.id.goog[workload-identity-test-ns/<ksa-name>]`
    `roles/iam.workloadIdentityUser` on
    `<gsa-name>@<project-id>.iam.gserviceaccount.com`, as an IAM binding in Config
    Connector YAML through `gcp-config-connector`.

3.  **Verify Example Pod:** Use existing asset
    `assets/workload-identity-pod.yaml` to test the configuration. Update the
    `<ksa-name>` in the file first, and propose it as a pull request.

### 3. Implement Network Policies

Control traffic flow between Pods using Network Policies. By default, all
traffic is allowed.

**Check Network Policy Enforcement & Dataplane:**

Before modifying cluster networking, inspect whether NetworkPolicy enforcement
is already active or provided natively by Dataplane V2:

```bash
gcloud container clusters describe <cluster-name> \
    --location <location> \
    --format='value(networkConfig.datapathProvider,networkPolicy.enabled)'
```

- If `datapathProvider` is `ADVANCED_DATAPATH` (Dataplane V2), NetworkPolicy
  enforcement is built-in natively via eBPF/Cilium from cluster creation. Calico
  addons cannot be enabled and are not needed.
- If `networkPolicy.enabled` is `True`, Calico enforcement is already enabled on nodes.
- If neither is active, enable Calico network policy enforcement using the two-step
  sequence below.

**Enable Network Policy Enforcement (non-DPv2 clusters):**

Enabling network policy enforcement on clusters without Dataplane V2 requires
two sequential changes in this order: first enable the Calico addon on the
control plane, then enable network policy enforcement on the nodes. GKE rejects
enforcement with HTTP 400 until the addon is enabled. Propose them as two pull
requests on the cluster's `ContainerCluster` through `gcp-config-connector`, the
second only after the first has applied:

1. Enable the NetworkPolicy addon on the control plane:
   `spec.addonsConfig.networkPolicyConfig.disabled: false`.
2. Enable NetworkPolicy enforcement on the nodes: `spec.networkPolicy.enabled: true`
   (node pools may be recreated; this can take several minutes).

**Apply Default Deny Policy:** Isolate namespaces by denying all ingress and
egress traffic by default.

**Propose `assets/default-deny-netpol.yaml` in `<target-namespace>`, the namespace
you want to isolate, as a pull request through `submit-suggestion`.**

### 4. GKE Sandbox (gVisor) Pod Isolation

Run untrusted workloads in a sandbox for extra kernel isolation. *(Note:
Enabling Shielded Nodes (`--enable-shielded-nodes`) and GKE Sandbox
(`--enable-gke-sandbox`) at the cluster control plane level are platform-level
actions covered in the `gke-platform-security` skill.)*

**Run a Sandboxed Pod:** Add `runtimeClassName: gvisor` to your Pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sandboxed-pod
spec:
  runtimeClassName: gvisor
  containers:
  - name: app
    image: nginx
```

### 5. Pod Security Standards

Enforce security policies on namespaces using labels.

**Enforce Restricted Profile:** set these labels on the namespace's manifest,
proposed as a pull request through `submit-suggestion`:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
```

> [!NOTE] Using `latest` ensures you use the policies corresponding to the
> cluster's current version. You can pin it to a specific version (e.g.,
> `v1.30`) to lock down the namespace to policies of a specific release.

### 6. Secret Manager Integration (CSI Driver)

Mount secrets from Google Cloud Secret Manager directly as volumes in your pods.

**Prerequisites**: Secret Manager CSI driver must be enabled on the cluster.

**Example SecretProviderClass:**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: my-secret-provider
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/<project-id>/secrets/my-secret/versions/latest"
        fileName: "my-secret-file"
```

**Example Pod Spec excerpt:**

```yaml
spec:
  containers:
    - name: my-app
      volumeMounts:
        - name: secrets-store-inline
          mountPath: "/mnt/secrets"
          readOnly: true
  volumes:
    - name: secrets-store-inline
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "my-secret-provider"
```

### 7. Enable Network Policy Logging

If using GKE Dataplane V2, you can log allowed and denied connections.

**Steps:**

1.  Configure the `NetworkLogging` custom resource.

**Example NetworkLogging Manifest:**

```yaml
apiVersion: networking.gke.io/v1alpha1
kind: NetworkLogging
metadata:
  name: default
spec:
  cluster:
    allow:
      log: true
      delegate: true
    deny:
      log: true
      delegate: true
```

This will log connection details to Cloud Logging.

### 8. Disable Unused ServiceAccount Token Auto-Mounting

Workloads mount a Kubernetes API credential by default unless `automountServiceAccountToken: false` is set. Propose `automountServiceAccountToken: false` on a workload's pod template **only** after every pre-flight check below passes on the live cluster. Do not `exec` into pods or read container logs to probe token usage, and never mutate live cluster objects directly.

**Step 1 — Inspect live state on the target cluster:**

When a Cluster Agent exists for the target cluster, delegate the read-only pre-flight inspection to it; when inspecting directly from the Platform Agent, pass the target's own kubeconfig (`$HERMES_HOME/.kubeconfigs/kubeconfig_<project>_<cluster>_<location>.yaml`, fetched per **gke-basics**, "Cluster Credentials") with `--kubeconfig` on every read:

```bash
kubectl -n <namespace> get deployments,statefulsets,daemonsets,jobs,cronjobs,pods,serviceaccounts,rolebindings -o json --kubeconfig "<target-kubeconfig>"
kubectl get clusterrolebindings -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.roleRef.name}{"\t"}{.subjects}{"\n"}{end}' --kubeconfig "<target-kubeconfig>"
```

**Step 2 — Enforce all four pre-flight gates per workload:**

Clear a workload for remediation **only** when all four conditions hold:

1.  **Declared ServiceAccount without existing opt-out:** The pod template's `serviceAccountName` (defaulting to `default` when omitted) exists as a `ServiceAccount` in `<namespace>`, and neither the pod template nor the `ServiceAccount` already sets `automountServiceAccountToken: false`.
2.  **Zero RBAC grants:** Zero `RoleBindings` in `<namespace>` and zero `ClusterRoleBindings` list the `ServiceAccount` in `subjects` (a `RoleBinding` subject with an omitted `namespace` applies to the binding's own namespace). Also stop if any non-baseline binding (`system:basic-user`, `system:discovery`, `system:public-info-viewer`, and `system:service-account-issuer-discovery` excepted) grants a role to `Group` `system:authenticated`, `system:serviceaccounts`, or `system:serviceaccounts:<namespace>`.
3.  **Zero Workload Identity or Vault injector annotations:** The `ServiceAccount` has **no** `iam.gke.io/gcp-service-account` annotation in `metadata.annotations` (Workload Identity binds permissions in Google Cloud IAM rather than Kubernetes RBAC, so zero RBAC bindings does not mean the identity is unused), and the pod template has **no** `vault.hashicorp.com/agent-inject` annotation set to `"true"`, `"True"`, `"TRUE"`, `"t"`, `"T"`, or `"1"`.
4.  **No explicit `/var/run/secrets/kubernetes.io/serviceaccount` container mount:** No container in the workload's pod template (`containers`, `initContainers`, or `ephemeralContainers` — and on an unowned `Pod`, no `volumeMounts` entry other than Kubernetes' admission-injected `kube-api-access-*` volume) mounts `/var/run/secrets/kubernetes.io/serviceaccount` or a subpath beneath it.

**Step 3 — Open one GitOps pull request for cleared workloads only:**

1.  Prepare a branch with `submit-suggestion` (or reuse the workspace already prepared in `submit-suggestion` Step 1) and locate the workload manifests under `clusters/<cluster-name>/...`.
2.  Edit **only** the manifest file(s) of workloads that passed all four pre-flight gates, adding `automountServiceAccountToken: false` on the pod template (`spec.template.spec.automountServiceAccountToken: false`, or `spec.jobTemplate.spec.template.spec.automountServiceAccountToken: false` on a `CronJob`), not on a shared `ServiceAccount`. Leave every excluded workload's manifest file untouched.
3.  Submit **one** pull request via `submit-suggestion`. In your final report, state that `automountServiceAccountToken: false` is proposed for the cleared workload(s), name every excluded workload alongside the specific pre-flight check that excluded it (RBAC binding, `iam.gke.io/gcp-service-account` annotation, Vault injector annotation, or explicit `/var/run/secrets/kubernetes.io/serviceaccount` mount), and link the pull request URL.

```yaml
spec:
  template:
    spec:
      serviceAccountName: <ksa-name>
      automountServiceAccountToken: false
```

## Best Practices

1.  **Least Privilege:** Always use Workload Identity with minimal IAM roles.
    Avoid using Node default service accounts.
2.  **Network Isolation:** Use Network Policies to restrict Pod-to-Pod
    communication. Enable Network Policy Logging for visibility.
3.  **Image Security:** Use Binary Authorization to ensure only trusted images
    are deployed.
4.  **Secret Management**: Use Secret Manager CSI driver instead of default
    Kubernetes secrets for sensitive data.
5.  **Pod Security**: Enforce `baseline` or `restricted` Pod Security Standards
    on all non-system namespaces.
6.  **Policy Enforcement**: Consider using **Policy Controller** (Gatekeeper) to
    enforce custom security and compliance policies across the cluster.
7.  **ServiceAccount Token Hygiene**: Propose `automountServiceAccountToken: false`
    on pod templates only after confirming zero RBAC bindings, zero
    `iam.gke.io/gcp-service-account` or Vault injector annotations, and no
    explicit `/var/run/secrets/kubernetes.io/serviceaccount` container mount.

## Resources

-   [Workload Identity Federation for GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
-   [GKE Network Policies](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy)
-   [Pod Security Standards in GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/podsecurityadmission)
-   [Google Secret Manager CSI Driver](https://cloud.google.com/secret-manager/docs/secret-manager-managed-csi-component)
-   [GKE Dataplane V2 Network Logging](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy-logging)
