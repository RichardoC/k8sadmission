# Kubernetes Dynamic Admission Review Plugin

## Introduction

This plugin extends Falco to support [Kubernetes Admission Review Requests](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#response) such as from [kube-audit-rest](https://github.com/RichardoC/kube-audit-rest) as a new data source.
These events are logged by kube-audit-rest when almost every creation/mutation is performed though there are some [limitations](https://github.com/RichardoC/kube-audit-rest#known-limitations-and-warnings). By monitoring the audit logs, this plugins provides high visibility over the activity in your cluster allows detecting malicious behavior.

### Functionality

This plugin supports consuming Kubernetes Admission Review Requests from a file. For files, the plugins expects content to be [in JSONL format](https://jsonlines.org/), where each line represents a JSON object, containing one or more audit events.


## Capabilities

The `k8sadmission` plugin implements both the event sourcing and the field extraction capabilities of the Falco Plugin System.

### Event Source

The event source for Kubernetes Audit Events is `k8s_admission`.

TODO: actually fill in the Supported fields, everything after here should be checked!

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
|                        NAME                        |      TYPE       |      ARG      |                                                                                                 DESCRIPTION                                                                                                  |
|----------------------------------------------------|-----------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `kar.auditid`                                       | `string`        | None          | The unique id of the audit event                                                                                                                                                                             |
| `kar.stage`                                         | `string`        | None          | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)                                                                                                                                          |
| `kar.auth.decision`                                 | `string`        | None          | The authorization decision                                                                                                                                                                                   |
| `kar.auth.reason`                                   | `string`        | None          | The authorization reason                                                                                                                                                                                     |
| `kar.user.name`                                     | `string`        | None          | The user name performing the request                                                                                                                                                                         |
| `kar.user.groups`                                   | `string (list)` | None          | The groups to which the user belongs                                                                                                                                                                         |
| `kar.impuser.name`                                  | `string`        | None          | The impersonated user name                                                                                                                                                                                   |
| `kar.verb`                                          | `string`        | None          | The action being performed                                                                                                                                                                                   |
| `kar.uri`                                           | `string`        | None          | The request URI as sent from client to server                                                                                                                                                                |
| `kar.uri.param`                                     | `string`        | Key, Required | The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, kar.uri.param[key] is val).                                                                                                      |
| `kar.target.name`                                   | `string`        | None          | The target object name                                                                                                                                                                                       |
| `kar.target.namespace`                              | `string`        | None          | The target object namespace                                                                                                                                                                                  |
| `kar.target.resource`                               | `string`        | None          | The target object resource                                                                                                                                                                                   |
| `kar.target.subresource`                            | `string`        | None          | The target object subresource                                                                                                                                                                                |
| `kar.req.binding.subjects`                          | `string (list)` | None          | When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding                                                                                       |
| `kar.req.binding.role`                              | `string`        | None          | When the request object refers to a cluster role binding, the role being linked by the binding                                                                                                               |
| `kar.req.binding.subject.has_name`                  | `string`        | Key, Required | Deprecated, always returns "N/A". Only provided for backwards compatibility                                                                                                                                  |
| `kar.req.configmap.name`                            | `string`        | None          | If the request object refers to a configmap, the configmap name                                                                                                                                              |
| `kar.req.configmap.obj`                             | `string`        | None          | If the request object refers to a configmap, the entire configmap object                                                                                                                                     |
| `kar.req.pod.containers.image`                      | `string (list)` | Index         | When the request object refers to a pod, the container's images.                                                                                                                                             |
| `kar.req.container.image`                           | `string`        | None          | Deprecated by kar.req.pod.containers.image. Returns the image of the first container only                                                                                                                     |
| `kar.req.pod.containers.image.repository`           | `string (list)` | Index         | The same as req.container.image, but only the repository part (e.g. falcosecurity/falco).                                                                                                                    |
| `kar.req.container.image.repository`                | `string`        | None          | Deprecated by kar.req.pod.containers.image.repository. Returns the repository of the first container only                                                                                                     |
| `kar.req.pod.host_ipc`                              | `string`        | None          | When the request object refers to a pod, the value of the hostIPC flag.                                                                                                                                      |
| `kar.req.pod.host_network`                          | `string`        | None          | When the request object refers to a pod, the value of the hostNetwork flag.                                                                                                                                  |
| `kar.req.container.host_network`                    | `string`        | None          | Deprecated alias for kar.req.pod.host_network                                                                                                                                                                 |
| `kar.req.pod.host_pid`                              | `string`        | None          | When the request object refers to a pod, the value of the hostPID flag.                                                                                                                                      |
| `kar.req.pod.containers.host_port`                  | `string (list)` | Index         | When the request object refers to a pod, all container's hostPort values.                                                                                                                                    |
| `kar.req.pod.containers.privileged`                 | `string (list)` | Index         | When the request object refers to a pod, the value of the privileged flag for all containers.                                                                                                                |
| `kar.req.container.privileged`                      | `string`        | None          | Deprecated by kar.req.pod.containers.privileged. Returns true if any container has privileged=true                                                                                                            |
| `kar.req.pod.containers.allow_privilege_escalation` | `string (list)` | Index         | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers                                                                                                   |
| `kar.req.pod.containers.read_only_fs`               | `string (list)` | Index         | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers                                                                                                     |
| `kar.req.pod.run_as_user`                           | `string`        | None          | When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers                         |
| `kar.req.pod.containers.run_as_user`                | `string (list)` | Index         | When the request object refers to a pod, the runAsUser uid for all containers                                                                                                                                |
| `kar.req.pod.containers.eff_run_as_user`            | `string (list)` | Index         | When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified |
| `kar.req.pod.run_as_group`                          | `string`        | None          | When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers                      |
| `kar.req.pod.containers.run_as_group`               | `string (list)` | Index         | When the request object refers to a pod, the runAsGroup gid for all containers                                                                                                                               |
| `kar.req.pod.containers.eff_run_as_group`           | `string (list)` | Index         | When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified |
| `kar.req.pod.containers.proc_mount`                 | `string (list)` | Index         | When the request object refers to a pod, the procMount types for all containers                                                                                                                              |
| `kar.req.role.rules`                                | `string (list)` | None          | When the request object refers to a role/cluster role, the rules associated with the role                                                                                                                    |
| `kar.req.role.rules.apiGroups`                      | `string (list)` | Index         | When the request object refers to a role/cluster role, the api groups associated with the role's rules                                                                                                       |
| `kar.req.role.rules.nonResourceURLs`                | `string (list)` | Index         | When the request object refers to a role/cluster role, the non resource urls associated with the role's rules                                                                                                |
| `kar.req.role.rules.verbs`                          | `string (list)` | Index         | When the request object refers to a role/cluster role, the verbs associated with the role's rules                                                                                                            |
| `kar.req.role.rules.resources`                      | `string (list)` | Index         | When the request object refers to a role/cluster role, the resources associated with the role's rules                                                                                                        |
| `kar.req.pod.fs_group`                              | `string`        | None          | When the request object refers to a pod, the fsGroup gid specified by the security context.                                                                                                                  |
| `kar.req.pod.supplemental_groups`                   | `string (list)` | None          | When the request object refers to a pod, the supplementalGroup gids specified by the security context.                                                                                                       |
| `kar.req.pod.containers.add_capabilities`           | `string (list)` | Index         | When the request object refers to a pod, all capabilities to add when running the container.                                                                                                                 |
| `kar.req.service.type`                              | `string`        | None          | When the request object refers to a service, the service type                                                                                                                                                |
| `kar.req.service.ports`                             | `string (list)` | Index         | When the request object refers to a service, the service's ports                                                                                                                                             |
| `kar.req.pod.volumes.hostpath`                      | `string (list)` | Index         | When the request object refers to a pod, all hostPath paths specified for all volumes                                                                                                                        |
| `kar.req.volume.hostpath`                           | `string`        | Key, Required | Deprecated by kar.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume                                                                                              |
| `kar.req.pod.volumes.flexvolume_driver`             | `string (list)` | Index         | When the request object refers to a pod, all flexvolume drivers specified for all volumes                                                                                                                    |
| `kar.req.pod.volumes.volume_type`                   | `string (list)` | Index         | When the request object refers to a pod, all volume types for all volumes                                                                                                                                    |
| `kar.resp.name`                                     | `string`        | None          | The response object name                                                                                                                                                                                     |
| `kar.response.code`                                 | `string`        | None          | The response code                                                                                                                                                                                            |
| `kar.response.reason`                               | `string`        | None          | The response reason (usually present only for failures)                                                                                                                                                      |
| `kar.useragent`                                     | `string`        | None          | The useragent of the client who made the request to the apiserver                                                                                                                                            |
| `kar.sourceips`                                     | `string (list)` | Index         | The IP addresses of the client who made the request to the apiserver                                                                                                                                         |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: k8sadmission
    library_path: libk8sadmission.so
    init_config:
      sslCertificate: /etc/falco/falco.pem
    open_params: "http://:9765/k8s-audit"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8sadmission, json]
```

**Initialization Config**:
- `sslCertificate`: The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)
- `maxEventSize`: Maximum size of single audit event (Default: 262144)
- `webhookMaxBatchSize`: Maximum size of incoming webhook POST request bodies (Default: 12582912)
- `useAsync`: If true then async extraction optimization is enabled (Default: true)

**Open Parameters**:
- `http://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTP webserver
- `https://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTPS webserver
- `no scheme`: Opens an event stream by reading the events from a file on the local filesystem. The params string is interpreted as a filepath


### Rules

The `k8sadmission` plugin ships with a default set of ruleset (see `rules/` directory).
The official ruleset depends on the `json` plugin, which motivates its presence in the `falco.yaml` sample showed above.

### Building and running locally

```bash

make

```

### Running

This plugin requires Falco with version >= **0.32.0**.
```shell
falco -c falco.yaml -r k8s_audit_rules.yaml
```
```shell
14:09:12.581541000: Warning Pod started with privileged container (user=system:serviceaccount:kube-system:replicaset-controller pod=nginx-deployment-5cdcc99dbf-rgw6z ns=default image=nginx)
Driver Events:0
Driver Drops:0
Elapsed time: 0.004, Captured Events: 1, 224.62 eps
Events detected: 1
Rule counts by severity:
   WARNING: 1
Triggered rules by rule name:
   Create Privileged Pod: 1
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
```

### Steps to add new parsing and rules

#### Declare the new fields

Add them to `func (k *Plugin) Fields() []sdk.FieldEntry {` in `pkg/k8sadmission/fields.go`

#### Add the new field extractions

Add them to `func (e *Plugin) ExtractFromJSON(req sdk.ExtractRequest, jsonValue *fastjson.Value) error {` in `pkg/k8sadmission/extract.go`
 
#### Add the new rules
Update `rules/k8s_admission_rules.yaml`

#### Add a test for the new rule and extraction
Update `testing/generate-data.sh` and add any yaml that are required to `testing/k8s`

#### Running the tests


```bash
rdctl shell sudo cat "/var/lib/kubelet/pods/$(kubectl -n kube-audit-rest get po -l app=kube-audit-rest -ojsonpath='{.items[0].metadata.uid}' )/volumes/kubernetes.io~empty-dir/tmp/kube-audit-rest.log" > test_files/kube-audit-rest.log.huge.json ; ./examples/running-locally/run.sh
```
TODO, add testing steps


## Credits

This module borrows heavily from the [k8saudit plugin](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) code
