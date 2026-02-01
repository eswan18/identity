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
└── cloudflared/
    └── deployment.yaml     # Cloudflare Tunnel connector
```

## Environments

| Environment | Namespace | Replicas | Purpose |
|-------------|-----------|----------|---------|
| Production | `identity-prod` | 2 | Live traffic via `identity.ethanswan.com` |
| Staging | `identity-staging` | 1 | Testing via `kubectl port-forward` |

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

## Cluster Details

- **Provider:** Google Kubernetes Engine (GKE)
- **Project:** `ethans-services`
- **Cluster:** `main-cluster`
- **Zone:** `us-central1-a`
- **Node Pools:**
  - `default-pool` - Stable node for critical workloads
  - `spot-pool` - Spot/preemptible node for cost savings

## Networking

Traffic flows through Cloudflare Tunnel (no external load balancer):

```
Internet → Cloudflare Edge → Cloudflare Tunnel → ClusterIP Service → Pods
```

The `cloudflared` deployment in the `cloudflared` namespace maintains the tunnel connection. Routes are configured in the Cloudflare Zero Trust dashboard.

## Deploying

Preview changes:
```bash
kubectl kustomize k8s/staging/
kubectl kustomize k8s/prod/
```

Apply changes:
```bash
kubectl apply -k k8s/staging/
kubectl apply -k k8s/prod/
```

Restart deployments (to pull new images):
```bash
kubectl rollout restart deployment/identity -n identity-staging
kubectl rollout restart deployment/identity -n identity-prod
```

## Accessing Staging

Staging is not publicly exposed. Use port-forwarding:
```bash
kubectl port-forward svc/identity -n identity-staging 8080:80
# Then access http://localhost:8080
```

## CI/CD

**Current state:**
- Cloud Build triggers on push to `main` branch
- Builds and pushes image to `us-central1-docker.pkg.dev/ethans-services/containers/identity:latest`
- Deployment requires manual `kubectl rollout restart`

**Planned:**
- ArgoCD for automated deployments
- Push to main → auto-deploy to staging
- Manual promotion to prod

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

# Debug a pod
kubectl describe pod <pod-name> -n <namespace>

# Force rebalance across nodes (delete one pod)
kubectl delete pod <pod-name> -n identity-prod
```
