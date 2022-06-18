#!/bin/bash

# Script to create public and private OpenSSL keys to be used to encrypt
# files obtained as part of audit data requests
# J Eduardo Martinez 
# 11-Aug-2020 - Version 1
# 11-Aug-2020 - Version 1.1 - Added validation for local OS and 'echo' command
#
# Instructions:
#
# 1. Run the script. It will create automatically two files: private.pem and
#    public.pm, which are the private and public keys.
# 2. Include the files encrypt.sh and public.pm as part of your data request

BIN=/usr/bin
OPENSSL=${BIN}/openssl
PRIVKEY=private.pem
PUBKEY=public.pem

OS=$(${BIN}/uname)

case $OS in
   "Darwin") ECHOCMD=echo ;;        # 'echo' command is built-in in MacOS
          *) ECHOCMD=${BIN}/echo ;; # on other systems, it is a binary file
esac

$ECHOCMD [\+] Creating OpenSSL private key ...
$OPENSSL genrsa -out $PRIVKEY 2048 > /dev/null 2>&1

if [ $? -eq 0 ]; then
   $ECHOCMD [\+] OpenSSL private key created ...
   ${BIN}/chmod 700 $PRIVKEY 2>/dev/null || /bin/chmod 700 $PRIVKEY
else
   $ECHOCMD [\!] Error creating OpenSSL private key. 
   exit 1 
fi

$ECHOCMD [\+] Creating OpenSSL public key ...
$OPENSSL rsa -in $PRIVKEY -out $PUBKEY -outform PEM -pubout > /dev/null 2>&1

if [ $? -eq 0 ]; then
   $ECHOCMD [\+] OpenSSL public key created ...
else
   $ECHOCMD [\!] Error creating OpenSSL public key. 
   exit 2 
fi
exit 0
