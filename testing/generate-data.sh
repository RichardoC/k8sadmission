# - rule: Disallowed K8s User
# working
kubectl create ns disallowed-user
# - rule: Create Disallowed Pod
# not working
kubectl run -i -t busybox-creation --image=busybox --restart=Never
# - rule: Create Privileged Pod
# not working
kubectl apply -f testing/k8s/privileged-pod.yaml 
# # - rule: Create Sensitive Mount Pod
# not working
kubectl apply -f testing/k8s/sensitive-path-pod.yaml 
# - rule: Create HostNetwork Pod
# not working
kubectl apply -f testing/k8s/hostnetwork-pod.yaml 
# - rule: Create HostPid Pod
# not working
kubectl apply -f testing/k8s/hostpid-pod.yaml
# - rule: Create HostIPC Pod
kubectl apply -f testing/k8s/hostipc-pod.yaml
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
