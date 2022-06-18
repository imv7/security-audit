#!/bin/bash

# Script to decrypt a file using the OpenSSL private key
# and a passphrase that was encrypted using the public key
# J Eduardo Martinez
# 11-Aug-2020 - Version 1
# 11-Aug-2020 - Version 1.1 - Added validation for local OS and 'echo' command
# 11-Aug-2020 - Version 1.2 - Added usage instructions
#
# Instructions:
#
# 1. Run this script to decrypt. Run in from the same directory where the two
#    .enc files provided as response to the data request were downloaded. The
#    script receives as argument the file that is going to be decrypted
# 2. The private key 'private.pem' should be on the same directory as well


BIN=/usr/bin
OPENSSL=${BIN}/openssl
PRIVKEY=private.pem
CIPHER=aes-256-cbc
PHRASE=au.dit

OS=$(${BIN}/uname)

case $OS in
   "Darwin") ECHOCMD=echo ;;        # 'echo' command is built-in in MacOS
          *) ECHOCMD=${BIN}/echo ;; # on other systems, it is a binary file
esac

if [ "$1" = "" ]; then
   $ECHOCMD "[!] A file must be passed as an argument"
   $ECHOCMD "[!] Usage: $0 filename"
   exit 1
else
   file=$1
   if [ ! -f "$file" ]; then
      $ECHOCMD "[!] The encrypted file \"${file}\" does not exist"
      $ECHOCMD "[!] Aborting decryption of file \"${file}\""
      exit 5
   else
      decrypted=$($ECHOCMD $file | ${BIN}/sed 's/.enc$//')
   fi
fi

if [ ! -f "$PRIVKEY" ]; then
   $ECHOCMD "[!] The private key is not available"
   $ECHOCMD "[!] Aborting decryption of file \"${file}\""
   exit 3
fi

if [ ! -f "${PHRASE}.enc" ]; then
   $ECHOCMD "[!] The encrypted passphrase  is not available"
   $ECHOCMD "[!] Aborting decryption of file \"${file}\""
   exit 4
fi

$ECHOCMD [\+] Decrypting file \"${file}\"

$OPENSSL rsautl -decrypt -inkey ${PRIVKEY} -in ${PHRASE}.enc -out ${PHRASE} > /dev/null 2>&1
$OPENSSL enc -d -${CIPHER} -in $file -out ${decrypted} -pass file:${PHRASE} > /dev/null 2>&1

if [ $? -eq 0 ]; then
   $ECHOCMD [\+] File \"${file}\" decrypted successfully ...
else
   $ECHOCMD [!] There was an error decrypting file \"${file}\" ...
   exit 2
fi
exit 0
