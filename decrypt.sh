# Replace "/path/to/encrypted_folder.tar.gz.gpg" with the path to the encrypted folder
# Replace "encryption_key.txt" with the path to the file containing the encryption key
# Replace "/path/to/output/folder" with the desired path for the decrypted folder

# Decrypt the folder using the encryption key
gpg --decrypt --output /path/to/output/folder/encrypted_folder.tar.gz /path/to/encrypted_folder.tar.gz.gpg

# Extract the decrypted folder
tar -xzvf /path/to/output/folder/encrypted_folder.tar.gz -C /path/to/output/folder
