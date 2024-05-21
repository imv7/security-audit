#!/bin/bash
#Run the script
# This script will iterate over all storage accounts in your Azure subscription and print the information.
#Make sure you have authenticated with Azure CLI using az login before executing this script.


# Output file
output_file="storage_account_info.txt"

# Get all storage accounts in the subscription
storage_accounts=$(az storage account list --query "[].name" -o tsv)

# Print a message to the screen
echo "Information for storage accounts:" 

# Iterate through each storage account and list its access keys
for storage_account in $storage_accounts; do
    echo "Storage Account: $storage_account"
    az storage account keys list --account-name $storage_account
done | tee "$output_file"

echo "Information for all storage accounts have been saved to $output_file. Please remove sensitive information and send the file to the audit team."
