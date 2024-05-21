#!/bin/bash

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo "Error: GPG (GNU Privacy Guard) is not installed. Please install it."
    exit 1
fi

# Folder to encrypt
folder_to_encrypt="/path/to/folder"

# GPG recipient
recipient_name="Recipient Name"

# Encrypt the folder
gpg --output "${folder_to_encrypt}.tar.gz.gpg" --symmetric "${folder_to_encrypt}.tar.gz"

# Save the encryption key to a file
echo "Hello ${recipient_name},
Please find attached the encryption key for the encrypted folder." > encryption_key.txt
gpg --export -a "${recipient_name}" >> encryption_key.txt

echo "Encryption key saved to encryption_key.txt."