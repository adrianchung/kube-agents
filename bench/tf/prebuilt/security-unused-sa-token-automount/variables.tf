# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Paired with bench/tasks/security-unused-sa-token-automount-pr/task.yaml.

variable "host_cluster_name" {
  type        = string
  description = "Name of the GKE cluster the scenario namespace is planted on; injected as TF_VAR_host_cluster_name by the eval runner."
}

variable "host_cluster_location" {
  type        = string
  description = "Region or zone of host_cluster_name."
}

variable "project_id" {
  type        = string
  description = "GCP project holding host_cluster_name; empty uses the active gcloud project."
  default     = ""
}

variable "namespace" {
  type        = string
  description = "Isolated namespace holding the four ServiceAccount pre-flight test workloads."
  default     = "seeded-sa-automount"
}

variable "gitops_repo" {
  type        = string
  description = "owner/name of the GitOps repository where the four workload manifests are planted for the unit."
  default     = ""
}

# Marker variable read by hack/ci-eval-pr.sh (BENCH_GITOPS_WRITE_VARIABLE):
# declaring it instructs the runner to mint a repo-scoped write token for this
# unit only and pass its path in TF_VAR_bench_gitops_write_token_file.
variable "bench_gitops_write_token_file" {
  type        = string
  description = "Path to a file holding a GitHub token with write access to gitops_repo."
  default     = ""
}

variable "gitops_base_branch" {
  type        = string
  description = "Optional isolated branch in gitops_repo to plant onto instead of the default branch (for local dev installs whose default branch is watched by live Argo CD)."
  default     = ""
}

variable "prow_build_id" {
  type        = string
  description = "Prow BUILD_ID of the run creating this infra."
  default     = ""
}

variable "prow_pull_number" {
  type        = string
  description = "Pull request number the run belongs to."
  default     = ""
}
