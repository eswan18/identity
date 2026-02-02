# Kubernetes Configuration

This directory contains Kubernetes manifests for the identity service, organized using [Kustomize](https://kustomize.io/).

## Structure

```
k8s/
├── base/                   # Shared configuration across all environments
│   ├── kustomization.yaml
│   ├── deployment.yaml     # Base deployment (probes, resources, ports, topology)
│   ├── service.yaml        # ClusterIP service
│   └── configmap.yaml      # Shared environment variables (7 values)
├── staging/
│   ├── kustomization.yaml
│   ├── deployment-patch.yaml       # Staging-specific: service account, secrets refs
│   ├── configmap-env.yaml          # Staging-specific env vars (3 values)
│   └── secret-provider-class.yaml  # References to staging secrets in GCP Secret Manager
├── prod/
│   ├── kustomization.yaml
│   ├── deployment-patch.yaml       # Prod-specific: service account, secrets refs
│   ├── configmap-env.yaml          # Prod-specific env vars (3 values)
│   └── secret-provider-class.yaml  # References to prod secrets in GCP Secret Manager
├── argocd/
│   ├── applications.yaml           # ArgoCD Application resources for staging + prod
│   └── image-updater.yaml          # ImageUpdater CR for auto-deploying to staging
└── cloudflared/
    └── deployment.yaml     # Cloudflare Tunnel connector
```

## Environments

| Environment | Namespace | Replicas | Purpose |
|-------------|-----------|----------|---------|
| Production | `identity-prod` | 2 | Live traffic via `identity.ethanswan.com` |
| Staging | `identity-staging` | 1 | Testing via `kubectl port-forward` |

## CI/CD Pipeline

Deployments are managed by **ArgoCD** with **ArgoCD Image Updater**.

### Staging (automatic)

1. Push code to `main` branch
2. Cloud Build builds and pushes a new image to Artifact Registry (tagged with git SHA)
3. ArgoCD Image Updater detects the new image (polls every 2 minutes)
4. ArgoCD automatically deploys the new image to staging

### Production (manual promotion)

1. Verify staging is healthy
2. In the ArgoCD UI, set the image tag on `identity-prod` to the git SHA running in staging
3. ArgoCD deploys the new image to production

### Config changes

Changes to manifests in `k8s/` are automatically synced by ArgoCD when pushed to `main`.
ArgoCD also self-heals: if someone manually changes something in the cluster, it reverts to match the repo.

### Checking deployed images

```bash
# See what's running in each environment
kubectl get pods -n identity-staging -o jsonpath='{.items[0].spec.containers[0].image}'
kubectl get pods -n identity-prod -o jsonpath='{.items[0].spec.containers[0].image}'
```

## Configuration Split

**Shared (in `base/configmap.yaml`):**
- EMAIL_FROM, EMAIL_PROVIDER
- HTTP_ADDRESS, TEMPLATES_DIR
- STORAGE_ENDPOINT, STORAGE_PROVIDER, STORAGE_REGION

**Environment-specific (in `{env}/configmap-env.yaml`):**
- JWT_ISSUER
- STORAGE_BUCKET
- STORAGE_PUBLIC_URL

**Secrets (in GCP Secret Manager, mounted via CSI driver):**
- DATABASE_URL
- JWT_PRIVATE_KEY
- RESEND_API_KEY
- STORAGE_ACCESS_KEY, STORAGE_SECRET_KEY, STORAGE_TOKEN

## Secrets Management

Secrets are stored in Google Secret Manager with naming convention:
```
identity_{environment}_{secret_name}
```

Example: `identity_prod_database_url`, `identity_staging_jwt_private_key`

Secrets are mounted into pods via:
1. **Workload Identity** - Kubernetes service accounts are linked to GCP service accounts
2. **Secrets Store CSI Driver** - Fetches secrets from GCP and creates Kubernetes secrets
3. **SecretProviderClass** - Defines which secrets to fetch per environment

### GCP Service Accounts
- `identity-prod-sa@ethans-services.iam.gserviceaccount.com` → `identity-prod-ksa`
- `identity-staging-sa@ethans-services.iam.gserviceaccount.com` → `identity-staging-ksa`
- `argocd-image-updater-sa@ethans-services.iam.gserviceaccount.com` → `argocd-image-updater` (reads Artifact Registry)

## Cluster Details

- **Provider:** Google Kubernetes Engine (GKE)
- **Project:** `ethans-services`
- **Cluster:** `main-cluster`
- **Zone:** `us-central1-a`
- **Node Pools:**
  - `default-pool-std2` - e2-standard-2 (2 vCPU, 8GB) stable node
  - `spot-pool-medium` - e2-medium (1 vCPU shared, 4GB) spot node for cost savings
- **Estimated cost:** ~$60/month for compute

## Networking

Traffic flows through Cloudflare Tunnel (no external load balancer):

```
Internet → Cloudflare Edge (SSL) → Cloudflare Tunnel → ClusterIP Service → Pods
```

The `cloudflared` deployment in the `cloudflared` namespace maintains the tunnel connection. Routes are configured in the Cloudflare Zero Trust dashboard.

## ArgoCD

ArgoCD runs in the `argocd` namespace and manages both environments. Access the UI:

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Open https://localhost:8080, login with admin credentials
```

ArgoCD Image Updater watches Artifact Registry for new images and auto-deploys to staging.
Registry auth uses a GCP service account key stored in `gar-pull-secret` in the `argocd` namespace.

## Accessing Staging

Staging is not publicly exposed. Use port-forwarding:
```bash
kubectl port-forward svc/identity -n identity-staging 8080:80
# Then access http://localhost:8080
```

## Useful Commands

```bash
# Check pod status
kubectl get pods -n identity-prod
kubectl get pods -n identity-staging

# View logs
kubectl logs -f deployment/identity -n identity-prod

# Check resource usage
kubectl top nodes
kubectl top pods -A

# Check node CPU/memory requests
kubectl describe nodes | grep -A5 "Allocated resources"

# ArgoCD Image Updater logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-image-updater --tail=20

# Debug a pod
kubectl describe pod <pod-name> -n <namespace>
```
