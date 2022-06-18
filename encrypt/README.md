# Script created by J Eduardo Martinez
Scripts to encrypt evidences from data requests, specially if they contain sensitive information (e.g. secrets). Tested on AIX, RedHat Linux, Kali Linux, and MacOS.

**create-keys.sh** - This script creates the pair of public and private encryption keys. The public key (public.pm) must be shared with clients so that they can encrypt the files (typically compressed) before posting them in the designated repository for each specific audit engagement.

![create-keys.sh GIF](https://github.com/imv7/encrypt/blob/master/img/create-keys.gif)


**encrypt.sh** - This script encrypts data using the public key and a random 32-bytes lenght passphrase. This script must be provided to the client along with the public key (public.pem). As output, this script generates two files, the encrypted data file (.enc extension) and an encrypted passphrase (au.dit.enc), these two files are packaged in a tar file, then they are compressed (.tar.gz extension) and make them ready to be delivered to the auditor.

![encrypt.sh GIF](https://github.com/imv7/encrypt/blob/master/img/encrypt.sh.gif)


**decrypt.sh** - This script decrypts the encrypted file using the private key and the encrypted passphrase (au.dit.enc) provided by the client.

![decrypt.sh GIF](https://github.com/imv7/encrypt/blob/master/img/decrypt.sh.gif)
