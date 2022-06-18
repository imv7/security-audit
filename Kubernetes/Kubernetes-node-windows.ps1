<# version 1.3 created by Igor Monteiro #>

<# Get namespace list #>
kubectl get namespaces --all-namespaces --field-selector metadata.name!=kube-system,metadata.name!=kube-public,metadata.name!=kube-node-lease,metadata.name!=ibm-cert-store,metadata.name!=kube-node-lease,metadata.name!=ibm-services-system,metadata.name!=ibm-system,metadata.name!=ibm-observe,metadata.name!=ibm-operators -o=custom-columns=NAME:.metadata.name --no-headers | Add-Content namespaces.log

<# Get pods #>
mkdir pods
foreach($podlist in Get-Content .\namespaces.log) {
    if($podlist -match $regex) {
        kubectl get pods --namespace $podlist -o=custom-columns=NAME:.metadata.name --no-headers | Add-Content podlist.log
    }
}

<# Get latest pod's logs #>
foreach($podnamens in Get-Content .\namespaces.log) {
    if($podnamens -match $regex) {
        $podnameid=kubectl get pods --namespace $podnamens -o=custom-columns=NAME:.metadata.name --no-headers 
        Write-Output $podnameid
        Write-Output $podnamens
         kubectl logs $podnameid --namespace $podnamens
        kubectl logs $podnameid --namespace $podnamens | Add-Content pods\$podnameid-ns-podnamens.log
    }
}

<# Describe pods #>
foreach($poddescribe in Get-Content .\podlist.log) {
    if($poddescribe -match $regex) {
        kubectl describe pods $poddescribe | Add-Content pods\$poddescribe-pod-describe.log
    }
}

<# yaml pods #>
foreach($podyaml in Get-Content .\podlist.log) {
    if($podyaml -match $regex) {
        kubectl get pod $podyaml -o yaml| Add-Content pods\$podyaml-pod.yaml
    }
}

<# Check the history of deployments including the revision #> 
mkdir deployments
foreach($deploymentns in Get-Content .\namespaces.log) {
    if($deploymentns -match $regex) {
        $deploymentid=kubectl get deployments --namespace $deploymentns -o=custom-columns=NAME:.metadata.name --no-headers
        Write-Output $deploymentns
        Write-Output $deploymentid
        kubectl rollout history deployment/$deploymentid --namespace $deploymentns  
        kubectl rollout history deployment/$deploymentid --namespace $deploymentns  | Add-Content deployments\deploymentids-ns-$deploymentns.log 
    }
} 
 
<# yaml serviceaccounts #> 
mkdir serviceaccounts
foreach($serviceaccns in Get-Content .\namespaces.log) {
    if($serviceaccns -match $regex) {
        $serviceaccid=kubectl get serviceaccounts --namespace $serviceaccns -o=custom-columns=NAME:.metadata.name --no-headers
        kubectl get serviceaccounts $serviceaccid --namespace $serviceaccns -o yaml 
        kubectl get serviceaccounts $serviceaccid --namespace $serviceaccns -o yaml | Add-Content serviceaccounts\serviceaccids-ns-$serviceaccns.yaml 
    }
} 

<# Get all worker nodes != master nodes #>
kubectl get node --selector='!node-role.kubernetes.io/master' | Add-Content workernodes.log

<# Get api versions. E.g: rbac.authorization.k8s.io/v1 #>
kubectl api-versions |  Add-Content api-versions.log


<# Check authorizations with user impersonation #>
mkdir cani
kubectl auth can-i list secrets --as=any-random-user --as-group=system:authenticated | Add-Content cani\list-secrets-anyrandomuser.log
kubectl auth can-i list secrets --as=system:serviceaccount:any-random-ns:any-random-sa | Add-Content cani\list-secrets-serviceaccount.log
kubectl auth can-i list secrets --as=system:anonymous --as-group=system:unauthenticated | Add-Content cani\list-secrets-anonymous.log
kubectl auth can-i create pod --as=any-random-user --as-group=system:authenticated | Add-Content  cani\create-pod-anyrandomuser.log
kubectl auth can-i create pod --as=system:serviceaccount:any-random-ns:any-random-sa | Add-Content cani\create-pod-serviceaccount.log
kubectl auth can-i create pod --as=system:anonymous --as-group=system:unauthenticated | Add-Content cani\create-pod-anonymous.log
kubectl auth can-i create deployments --as=any-random-user --as-group=system:authenticated | Add-Content  cani\create-deployments-anyrandomuser.log
kubectl auth can-i create deployments --as=system:serviceaccount:any-random-ns:any-random-sa | Add-Content cani\create-deployments-serviceaccount.log
kubectl auth can-i create deployments --as=system:anonymous --as-group=system:unauthenticated | Add-Content cani\create-deployments-anonymous.log
