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

# Scenario driver for bench/tasks/security-unused-sa-token-automount-pr.
#
# Plants four workloads in a dedicated namespace on host_cluster_name (via
# namespaced-plant) AND seeds the matching four YAML declarations into the
# GitOps repository (via plant.py):
#   1. order-processor (order-processor-sa): zero RoleBindings, zero
#      ClusterRoleBindings, zero Workload Identity IAM annotations, and no
#      container mounting /var/run/secrets/kubernetes.io/serviceaccount ->
#      SAFE to set automountServiceAccountToken: false.
#   2. config-watcher (config-watcher-sa): bound via RoleBinding -> EXCLUDED.
#   3. gcs-archiver (gcs-archiver-sa): annotated with iam.gke.io/gcp-service-account
#      -> EXCLUDED.
#   4. vault-fetcher (vault-fetcher-sa): container mounts a projected token at
#      /var/run/secrets/kubernetes.io/serviceaccount -> EXCLUDED.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0.0"
    }
  }
}

locals {
  ci_labels = {
    "managed-by"  = "kube-agents-bench"
    "build-id"    = var.prow_build_id != "" ? var.prow_build_id : "local"
    "pull-number" = var.prow_pull_number != "" ? var.prow_pull_number : "none"
  }

  manifest = <<-MANIFEST
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: order-processor-sa
      labels:
        app: order-processor
        managed-by: kube-agents-bench
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: order-processor
      labels:
        app: order-processor
        managed-by: kube-agents-bench
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: order-processor
      template:
        metadata:
          labels:
            app: order-processor
        spec:
          serviceAccountName: order-processor-sa
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: app
              image: registry.k8s.io/pause:3.10
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
              resources:
                requests:
                  cpu: 10m
                  memory: 16Mi
                limits:
                  memory: 32Mi
    ---
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: config-watcher-sa
      labels:
        app: config-watcher
        managed-by: kube-agents-bench
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: config-watcher-role
      labels:
        app: config-watcher
        managed-by: kube-agents-bench
    rules:
      - apiGroups: [""]
        resources: ["configmaps"]
        verbs: ["get", "list", "watch"]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: config-watcher-binding
      labels:
        app: config-watcher
        managed-by: kube-agents-bench
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: config-watcher-role
    subjects:
      - kind: ServiceAccount
        name: config-watcher-sa
        namespace: ${var.namespace}
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: config-watcher
      labels:
        app: config-watcher
        managed-by: kube-agents-bench
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: config-watcher
      template:
        metadata:
          labels:
            app: config-watcher
        spec:
          serviceAccountName: config-watcher-sa
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: watcher
              image: registry.k8s.io/pause:3.10
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
              resources:
                requests:
                  cpu: 10m
                  memory: 16Mi
                limits:
                  memory: 32Mi
    ---
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: gcs-archiver-sa
      labels:
        app: gcs-archiver
        managed-by: kube-agents-bench
      annotations:
        iam.gke.io/gcp-service-account: gcs-archiver@kube-agents-bench-no-such-fixture-project.iam.gserviceaccount.com
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: gcs-archiver
      labels:
        app: gcs-archiver
        managed-by: kube-agents-bench
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: gcs-archiver
      template:
        metadata:
          labels:
            app: gcs-archiver
        spec:
          serviceAccountName: gcs-archiver-sa
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: archiver
              image: registry.k8s.io/pause:3.10
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
              resources:
                requests:
                  cpu: 10m
                  memory: 16Mi
                limits:
                  memory: 32Mi
    ---
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: vault-fetcher-sa
      labels:
        app: vault-fetcher
        managed-by: kube-agents-bench
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: vault-fetcher
      labels:
        app: vault-fetcher
        managed-by: kube-agents-bench
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: vault-fetcher
      template:
        metadata:
          labels:
            app: vault-fetcher
        spec:
          serviceAccountName: vault-fetcher-sa
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: fetcher
              image: registry.k8s.io/pause:3.10
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop:
                    - ALL
              resources:
                requests:
                  cpu: 10m
                  memory: 16Mi
                limits:
                  memory: 32Mi
              volumeMounts:
                - name: custom-sa-token
                  mountPath: /var/run/secrets/kubernetes.io/serviceaccount
                  readOnly: true
          volumes:
            - name: custom-sa-token
              projected:
                sources:
                  - serviceAccountToken:
                      path: token
                      expirationSeconds: 3600
  MANIFEST

  gitops_settings = {
    SA_AUTOMOUNT_EVAL_GITOPS_REPO        = var.gitops_repo
    SA_AUTOMOUNT_EVAL_CLUSTER_NAME       = var.host_cluster_name
    SA_AUTOMOUNT_EVAL_NAMESPACE          = var.namespace
    SA_AUTOMOUNT_EVAL_GITOPS_TOKEN_FILE  = var.bench_gitops_write_token_file
    SA_AUTOMOUNT_EVAL_GITOPS_BASE_BRANCH = var.gitops_base_branch
  }
}

module "plant" {
  source = "../../modules/namespaced-plant"

  host_cluster_name     = var.host_cluster_name
  host_cluster_location = var.host_cluster_location
  project_id            = var.project_id
  namespace             = var.namespace
  stack                 = "security-unused-sa-token-automount"
  labels                = local.ci_labels
  manifest              = local.manifest
}

resource "null_resource" "gitops_declarations" {
  triggers = merge(local.gitops_settings, {
    script = "${path.module}/plant.py"
    digest = filesha256("${path.module}/plant.py")
  })

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = local.gitops_settings
    command     = <<-EOT
      set -euo pipefail
      python3 "${path.module}/plant.py" plant
    EOT
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/bash", "-c"]
    environment = {
      SA_AUTOMOUNT_EVAL_GITOPS_REPO        = self.triggers.SA_AUTOMOUNT_EVAL_GITOPS_REPO
      SA_AUTOMOUNT_EVAL_CLUSTER_NAME       = self.triggers.SA_AUTOMOUNT_EVAL_CLUSTER_NAME
      SA_AUTOMOUNT_EVAL_NAMESPACE          = self.triggers.SA_AUTOMOUNT_EVAL_NAMESPACE
      SA_AUTOMOUNT_EVAL_GITOPS_TOKEN_FILE  = self.triggers.SA_AUTOMOUNT_EVAL_GITOPS_TOKEN_FILE
      SA_AUTOMOUNT_EVAL_GITOPS_BASE_BRANCH = self.triggers.SA_AUTOMOUNT_EVAL_GITOPS_BASE_BRANCH
    }
    command = <<-EOT
      set -euo pipefail
      python3 "${self.triggers.script}" teardown
    EOT
  }
}

output "cluster_name" {
  value = module.plant.cluster_name
}

output "cluster_location" {
  value = module.plant.cluster_location
}
