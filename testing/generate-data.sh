# - rule: Disallowed K8s User
# working
kubectl create ns disallowed-user
# - rule: Create Disallowed Pod
# working
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
# not working
kubectl apply -f testing/k8s/hostipc-pod.yaml
# - rule: Create NodePort Service
# working
kubectl apply -f testing/k8s/NodePort.yaml
# - rule: Create/Modify Configmap With Private Credentials
# TODO
# - rule: Exec Pod
# working
kubectl apply -f testing/k8s/sleep-forever-pod.yaml ;
kubectl exec -it busybox-sleep-forever whoami
# - rule: Attach to Pod
# working
kubectl apply -f testing/k8s/sleep-forever-pod.yaml ; 
kubectl attach -it busybox-sleep-forever & PID=$! ; sleep 2; kill $PID
# - rule: Portforward
# working
kubectl apply -f testing/k8s/NodePort.yaml ;
kubectl port-forward svc/nodeport 8888:80 & PID=$! ; sleep 2; kill $PID
# # - rule: EphemeralContainers Created
# - rule: Create Disallowed Namespace
# working
kubectl create ns disallowed-ns
# - rule: Pod Created in Kube Namespace
# not working
kubectl run busybox-creation-kube-system --image=busybox --restart=Never --namespace kube-system
kubectl -n kube-system delete pod busybox-creation-kube-system

# - rule: Service Account Created in Kube Namespace
# working
kubectl -n kube-system create sa naughty-sa
# - rule: System ClusterRole Modified/Deleted
# working
kubectl patch clusterrole.rbac.authorization.k8s.io/system:basic-user -p '{"metadata":{"labels":{"a":"b"}}}'
# - rule: Attach to cluster-admin Role
# working
kubectl create clusterrolebinding --clusterrole=cluster-admin --serviceaccount default:abc abc-cluster-admin
# - rule: ClusterRole With Wildcard Created
# working
kubectl create clusterrole --verb list --resource=* listy-mc-list-face
# - rule: ClusterRole With Write Privileges Created
# working
kubectl create clusterrole --verb create --resource=pods writy-mc-list-facey
# - rule: ClusterRole With Pod Exec Created
# not working, but detected by Notice Created Role/ClusterRole with write privileges
kubectl create role --verb create --resource pods/exec pod-exec-er
# - rule: K8s Deployment Created
# working
kubectl create deployment test-depl --image busybox
# - rule: K8s Deployment Deleted
# working
kubectl delete deployment test-depl 
# - rule: K8s Service Created
# working
kubectl create svc clusterip test-svc  --tcp=8080:8080
# - rule: K8s Service Deleted
# working
kubectl delete svc test-svc
# # - rule: K8s ConfigMap Created
# working
kubectl create cm test-cm
# # - rule: K8s ConfigMap Deleted
# working
kubectl delete cm test-cm
# - rule: K8s Namespace Created
# didn't work, matched Create Disallowed Namespace instead
kubectl create ns test-ns
# - rule: K8s Namespace Deleted
# didn't work
kubectl delete ns test-ns
# - rule: K8s Serviceaccount Created
# working
kubectl create sa test-sa-d
# - rule: K8s Serviceaccount Deleted
# working
kubectl delete sa test-sa-d
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
