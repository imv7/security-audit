#!/bin/bash
# Instructions:
#    b. Run the script.
#    e. Tar and zip /tmp/corpaudit_<HOSTNAME> directory and provide the file

# Get the hostname of the system
hostname=$(hostname)

# Generate a random string of 7 lowercase letters
random_string=$(head /dev/urandom | tr -dc 'a-z' | head -c 7)

# Output directory with hostname and random string
OUTPUT_DIR="/tmp/corpaudit_${hostname}_$random_string"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Unique output directory for audit created: $OUTPUT_DIR"

# Command 1
echo "1. Check Security Context Constraints (SCCs):"
oc get scc > "$OUTPUT_DIR/scc.txt"

# Command 2
echo "2. View Network Policies:"
oc get networkpolicy > "$OUTPUT_DIR/networkpolicy.txt"

# Command 3
echo "3. List Role-Based Access Control (RBAC) Policies:"
oc get rolebinding,role,clusterrolebinding,clusterrole > "$OUTPUT_DIR/rbac.txt"

# Command 4
echo "4. Display OAuth Server Configuration:"
oc get oauthclient,oauthclientauthorization > "$OUTPUT_DIR/oauth.txt"

# Command 5
echo "5. Verify Pod Security Policies (PSPs):"
oc get psp > "$OUTPUT_DIR/psp.txt"

# Command 6
echo "6. Check ImageStreams and ImageStreamTags:"
oc get imagestream,imagestreamtag > "$OUTPUT_DIR/imagestream.txt"

# Command 7
echo "7. Inspect Secrets:"
oc get secret > "$OUTPUT_DIR/secret.txt"

# Command 8
echo "8. Review Service Accounts:"
oc get serviceaccount > "$OUTPUT_DIR/serviceaccount.txt"

# Command 9
echo "9. Examine ConfigMaps:"
oc get configmap > "$OUTPUT_DIR/configmap.txt"

# Command 10
echo "10. Verify Persistent Volume Claims (PVCs) and Persistent Volumes (PVs):"
oc get pvc,pv > "$OUTPUT_DIR/pvc_pv.txt"

# Command 11
echo "11. Inspect Cluster Roles:"
oc get clusterrole,clusterrolebinding > "$OUTPUT_DIR/clusterrole.txt"

# Command 12
echo "12. Check Pod Security Policies (PSPs) and associated PodSecurityPolicy (PSP) objects:"
oc get psp,podsecuritypolicy > "$OUTPUT_DIR/podsecuritypolicy.txt"

# Command 13
echo "13. Check the worker nodes:"
oc get nodes --selector='node-role.kubernetes.io/worker' -o=jsonpath='{.items[*].metadata.name}' > "$OUTPUT_DIR/worker_nodes.txt"

echo "Output saved in $OUTPUT_DIR directory. Tar and zip that directory and send the file to the audit team."
