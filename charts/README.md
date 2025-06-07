# Kube Web Log Viewer Helm Chart

Helm chart for deploying the Kubernetes Web Log Viewer - a simple Kubernetes pod log viewer web app.

Give direct log access to your software engineers to see the logs without giving them access to the kubeconfig or other centralized log tools.

This application is explicity designed to only monitor logs of pods in the namespace it is deployed to. It can be easily adapted to view all pods in the cluster- but it may not scale well in larger environments.

![screenshot](kube-web-log-viewer.png)

## Installation

## Install from web

The name of the chart is web-viewer. The recommended release name is `<namespace>-log`

If you use this naming, the command:
```sh
helm install kube-system-log \
  --repo https://jessegoodier.github.io/kube-web-log-viewer web-viewer \
  -n kube-system
```

Will result in a Deployment named:

`kube-system-log-web-viewer`

Install using the default values:

```sh
# Install with default settings
helm install NAMESPACE-log \
  --repo https://jessegoodier.github.io/kube-web-log-viewer web-viewer
```

Disable retaining logs of pods that have been killed.:

```sh
# Install with custom values
helm install kube-web-log-viewer \
  ./charts/kube-web-log-viewer \
  --set previousPodLogs.enabled=false
```

Persist logs on restart:

```sh
# Install with persistent storage
helm install kube-web-log-viewer ./charts/kube-web-log-viewer -n log-viewer --create-namespace \
  --set storage.type=persistentVolume \
  --set storage.persistentVolume.size=10Gi
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.apiKey` | API authentication key (set to "no-key" or empty to disable) | `"no-key"` |
| `auth.existingSecret` | Use existing secret for API key | `""` |
| `auth.existingSecretKey` | Key in existing secret containing API key | `"api-key"` |
| `previousPodLogs.enabled` | Enable/disable log archival functionality | `true` |
| `previousPodLogs.retentionMinutes` | Log retention period in minutes (7 days default) | `10080` |
| `previousPodLogs.allowPurge` | Allow purging of previous pod logs | `true` |
| `storage.type` | Storage type: "emptyDir" or "persistentVolume" | `emptyDir` |
| `storage.persistentVolume.size` | PVC size when using persistent storage | `5Gi` |
| `storage.persistentVolume.storageClass` | Storage class for PVC | `""` |
| `storage.persistentVolume.accessModes` | Access modes for PVC | `["ReadWriteOnce"]` |
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Container image repository | `python` |
| `image.tag` | Container image tag | `"3.13-slim"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.ingressClassName` | Ingress class name | `""` |
| `ingress.hosts` | Ingress hosts configuration | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | See values.yaml |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `5001` |
| `resources.requests.memory` | Memory request | `"128Mi"` |
| `resources.requests.cpu` | CPU request | `"100m"` |
| `resources.limits.memory` | Memory limit | `"256Mi"` |
| `resources.limits.cpu` | CPU limit | `"1500m"` |
| `rbac.create` | Create RBAC resources | `true` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |

## Examples

### Custom Values File

Create a `custom-values.yaml` file:

```yaml
auth:
  apiKey: "my-secure-api-key"

previousPodLogs:
  enabled: true
  retentionMinutes: 20160  # 14 days
  allowPurge: false

storage:
  type: persistentVolume
  persistentVolume:
    size: 15Gi
    storageClass: "standard"

ingress:
  enabled: true
  ingressClassName: "nginx"
  hosts:
    - host: logs.mycompany.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts:
        - logs.mycompany.com
      secretName: logs-tls

resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "512Mi"
    cpu: "2000m"
```

Then install with:

```bash
helm install kube-web-log-viewer ./charts/kube-web-log-viewer \
  --repo https://jessegoodier.github.io/kube-web-log-viewer web-viewer \
  -f custom-values.yaml
```

## Features

- **Web-based log viewer** - Modern, responsive UI for viewing pod logs
- **Multi-container support** - Handle pods with multiple containers
- **Log archival** - Retain logs from terminated pods
- **Real-time search and filtering** - Find specific log entries quickly
- **Theme support** - Light and dark mode
- **API authentication** - Optional security via API keys
- **Namespace isolation** - Only access pods in configured namespace

## API Endpoints

The application exposes the following REST API endpoints:

- `GET /api/pods` - List pods and containers in namespace
- `GET /api/logs` - Fetch logs from active pods
- `GET /api/archived_pods` - List pods with archived logs
- `GET /api/archived_logs` - Fetch logs from archived pods
- `GET /api/logDirStats` - Get log directory statistics
- `POST /api/purgePreviousLogs` - Clean up archived logs

## Security

The chart creates minimal RBAC permissions:
- List pods in the target namespace
- Read pod logs in the target namespace

API key authentication is optional but recommended when exposing the ingress.

## Storage Considerations

### EmptyDir (Default)
- Logs are stored in the pod's ephemeral storage
- Data is lost when the pod is deleted or restarted
- Suitable for development or when log persistence is not required

### Persistent Volume
- Logs are stored on persistent storage
- Data survives pod restarts and deletions

## Contributing

For issues and contributions, please visit the [GitHub repository](https://github.com/jessegoodier/kube-web-log-viewer).