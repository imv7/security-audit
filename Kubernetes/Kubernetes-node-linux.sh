# version 1.3 created by Igor Monteiro
# Instructions to the audit client:
# 1) Connect to the kubernetes cluster, run the script, and share the results.
# 2) Requires authorization to execute kubectl get,describe,rollout history,auth can-i, api-versions.
# Instructions to the lab environment:
# Create a Kubernetes cluster in the IBM Public Cloud: https://cloud.ibm.com/kubernetes/, then follow the one-time setup instructions.

# Get role bindings authorize unauthenticated and authenticated users to read API
kubectl get clusterroles system:discovery -o yaml

# Get ExternalIPs of all nodes
echo "Get ExternalIPs of all nodes"
kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="ExternalIP")].address}' >> externalIPs.log

echo "Get the PSP"
kubectl get psp -o yaml >> psp.yaml

echo "Get the POD logs"
mkdir pods
kubectl get pods -o=custom-columns=NAME:.metadata.name --no-headers >>  podlist.log
 
# Describe pods 
echo "Describe the PODs"

cat podlist.log |
 while IFS= read -r poddescribe
 do
kubectl describe pods $poddescribe  >>  pods/$poddescribe-describe.log
 done

# Get the policies of the PODs
echo "Get the policies of the PODs"
cat podlist.log |
 while IFS= read -r podyaml
 do
 kubectl get pod $podyaml  -o yaml >>  pods/$podyaml-pod.yaml
 done

# Get containers 
echo "Get the containers in the PODs"
mkdir containers
kubectl get pod  -o=custom-columns=NAME:.metadata.name,CONTAINERS:.spec.containers[*].name >>  containers/containerlist.log

#Get the rollout history of the deployements
echo "Get the rollout history of the deployements"
mkdir deployments
kubectl get deployments  -o=custom-columns=NAME:.metadata.name --no-headers  >>  deploymentlist.log

cat deploymentlist.log |
 while IFS= read -r deployment
 do
 kubectl rollout history deployment/$deployment  >>  deployments/$deployment-deployment.log
 done
 
# Get the service accounts
echo "Get the service accounts"
kubectl get serviceaccounts  -o=custom-columns=NAME:.metadata.name --no-headers  >>  serviceaccountlist.log

cat serviceaccountlist.log |
 while IFS= read -r serviceaccount
 do
kubectl get serviceaccounts $serviceaccount  -o yaml >>  $serviceaccount-serviceaccount.yaml
 done

#echo Get the Kubernetes nodes
echo "Get the Kubernetes nodes"
kubectl get node  --selector='!node-role.kubernetes.io/master' >>  workernodes.log

#Get the API versions
echo "Get the API versions"
kubectl api-versions  |grep -v k8s >> api-versions.log

# Get the authorizations in the environment
echo "Get the authorizations in the environment"
mkdir cani
kubectl auth can-i list secrets --as=any-random-user --as-group=system:authenticated  >>  cani/list-secrets-anyrandomuser.log
kubectl auth can-i list secrets --as=system:serviceaccount:any-random-ns:any-random-sa  >>  cani/list-secrets-serviceaccount.log
kubectl auth can-i list secrets --as=system:anonymous --as-group=system:unauthenticated  >>  cani/list-secrets-anonymous.log
kubectl auth can-i create pod --as=any-random-user --as-group=system:authenticated  >>   cani/create-pod-anyrandomuser.log
kubectl auth can-i create pod --as=system:serviceaccount:any-random-ns:any-random-sa  >>  cani/create-pod-serviceaccount.log
kubectl auth can-i create pod --as=system:anonymous --as-group=system:unauthenticated  >>  cani/create-pod-anonymous.log
