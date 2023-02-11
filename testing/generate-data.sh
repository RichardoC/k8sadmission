# working
# - rule: Disallowed K8s User
kubectl create ns disallowed-user
# not working
# - rule: Create Disallowed Pod
kubectl run -i -t busybox-creation --image=busybox --restart=Never
# not working
# - rule: Create Privileged Pod
kubectl apply -f testing/k8s/privileged-pod.yaml 
# not working
# # - rule: Create Sensitive Mount Pod
kubectl apply -f testing/k8s/sensitive-path-pod.yaml 
# - rule: Create HostNetwork Pod

# - rule: Create HostPid Pod
# - rule: Create HostIPC Pod
# - rule: Create NodePort Service
# - rule: Create/Modify Configmap With Private Credentials
# # - rule: Anonymous Request Allowed
# - rule: Exec Pod
# - rule: Attach to Pod
# - rule: Portforward
# # - rule: EphemeralContainers Created
# - rule: Create Disallowed Namespace
# - rule: Pod Created in Kube Namespace
# - rule: Service Account Created in Kube Namespace
# - rule: System ClusterRole Modified/Deleted
# - rule: Attach to cluster-admin Role
# - rule: ClusterRole With Wildcard Created
# - rule: ClusterRole With Write Privileges Created
# - rule: ClusterRole With Pod Exec Created
# - rule: K8s Deployment Created
# - rule: K8s Deployment Deleted
# - rule: K8s Service Created
# - rule: K8s Service Deleted
# # - rule: K8s ConfigMap Created
# # - rule: K8s ConfigMap Deleted
# - rule: K8s Namespace Created
# - rule: K8s Namespace Deleted
# - rule: K8s Serviceaccount Created
# - rule: K8s Serviceaccount Deleted
# - rule: K8s Role/Clusterrole Created
# - rule: K8s Role/Clusterrole Deleted
# - rule: K8s Role/Clusterrolebinding Created
# - rule: K8s Role/Clusterrolebinding DeletedDisallowed
# - rule: K8s Secret Created
# - rule: K8s Secret Deleted
# # - rule: K8s Secret Get Successfully
# # - rule:  K8s Secret Get Unsuccessfully Tried
# # - rule: All K8s Audit Events
# - rule: Full K8s Administrative Access
# # - rule: Trigger on all events
# # - rule: Ingress Object without TLS Certificate Created
# - rule: Untrusted Node Successfully Joined the Cluster
