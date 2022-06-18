#!/bin/bash

# Script to encrypt a file using the OpenSSL public key
# J Eduardo Martinez   
# 11-Aug-2020 - Version 1
# 11-Aug-2020 - Version 1.1 - Added validation for local OS and 'echo' command
# 25-Sep-2020 - Version 1.2 - Added logic to compress the evidences file and the 
#                             encryption in a gzip file. Updated instructions.
#                             Update suggested by   in github issue
#                              
# 25-Sep-2020 - Version 1.3 - Added colors and pieces of code were organized
# 01-Oct-2020 - Version 1.4 - Added logic to identify which OSes support colors
#                             Added logic to validate if openssl is located in
#                             /usr/bin directory
# 12-Oct-2020 - Version 1.5 - Color codes updated to use \x1B. Solved conflict 
#                             with the filename used to create compressed file 
#
# Instructions:
#
# 1. Ask the sys-admin to gzip the evidence files, and then to run this script 
#    on the same directory. The encryption process will create two files with 
#    the .enc extension, one is the file containing the evidences, and the 
#    second is a file named 'au.dit.enc'
# 2. If the TAR and GZIP utilities are installed then the evidences file and 
#    and the 'au.dit.enc' file are packaged in a tar file and then compressed 
#    client must provide the file <hostname>.<date>.tar.gz as response to the
#    data request. If not then go to step 3. 
# 3. Ask the client to upload the two .enc files as their response to the 
#    data request.

colors(){

   COLORED=$1

   if [ "${COLORED}" = "Y" ]; then
        red="\x1B[0;91m"
      green="\x1B[0;92m"
       bold="\x1B[1m"
      reset="\x1B[0m"
      blink="\x1B[5m"
   fi

     bangred="${red}${bold}[!]${reset}"
   banggreen="${green}${bold}[!]${reset}"
    OK2audit="${banggreen}${green}${bold}${blink}"
}

# As a security best practice commands in scripts must be invoked using
# full paths 

    BIN=/usr/bin
OPENSSL=${BIN}/openssl
   GZIP=${BIN}/gzip
    TAR=${BIN}/tar
  UNAME=${BIN}/uname
ECHOCMD=${BIN}/echo
  RMCMD=${BIN}/rm
DATECMD=${BIN}/date
 CUTCMD=${BIN}/cut


 PUBKEY=public.pem
 CIPHER=aes-256-cbc
 PHRASE=au.dit
PLENGTH=32

OS=$(${UNAME} -s)

case $OS in
     "Darwin") ECHOCMD="echo -e"         # 'echo' command is built-in in MacOS
                 RMCMD=/bin/rm        # 'rm' command is in /bin in MacOS
               DATECMD=/bin/date      # 'date' command is in /bin in MacOS
               colors Y ;;
'AIX'|'SunOS'|'OpenBSD'|'NetBSD'|'FreeBSD') 
               colors N ;;
            *) ECHOCMD="${ECHOCMD} -e" 
               colors Y ;;
esac


if [ "$1" = "" ]; then
   $ECHOCMD "$bangred A file must be passed as an argument"
   $ECHOCMD "$banggreen Usage: $0 filename"
   exit 1
else
   file=$1
   if [ ! -f "$file" ]; then
      $ECHOCMD "$bangred The file \"${file}\" does not exist"
      $ECHOCMD "$bangred Aborting encryption of file \"${file}\""
      exit 3
   fi
fi

if [ ! -f "$PUBKEY" ]; then
   $ECHOCMD "$bangred The public key is not available"
   $ECHOCMD "$banggreen Copy the public key \"public.pem\" provided by the"
   $ECHOCMD "    auditor into this directory"
   exit 4
fi

if [ ! -f "$OPENSSL" ]; then
   $ECHOCMD "$bangred The openssl binary file could not be located in /usr/bin"
   $ECHOCMD "    encryption cannot be performed. Contact the auditor for"
   $ECHOCMD "    instructions"
   exit 5
fi

$ECHOCMD $banggreen Encrypting file \"${file}\"

$OPENSSL rand   -base64  $PLENGTH > $PHRASE
$OPENSSL rsautl -encrypt -inkey $PUBKEY -pubin -in $PHRASE -out ${PHRASE}.enc > /dev/null 2>&1
$OPENSSL enc -$CIPHER -salt -in ${file} -out ${file}.enc -pass file:$PHRASE   > /dev/null 2>&1

if [ $? -eq 0 ]; then

   $ECHOCMD $banggreen File \"${file}\" encrypted successfully ...

   if [ -f $GZIP -a -f $TAR ]; then
      $ECHOCMD  $banggreen "Preparing compressed file for the auditor ..."

        HOSTNAME=$(${UNAME} -n | ${CUTCMD} -d'.' -f1)
           TODAY=$(${DATECMD} "+%y%m%d%H%M%S")
      COMPRESSED=${HOSTNAME}.${TODAY}.tar

      $TAR -cvf ${COMPRESSED} ${file}.enc ${PHRASE}.enc  >/dev/null 2>&1
      $GZIP     ${COMPRESSED}                            >/dev/null 2>&1
      $RMCMD    ${PHRASE}*    ${file}*                   >/dev/null 2>&1

      $ECHOCMD  $OK2audit Send file \"${COMPRESSED}.gz\" to the auditor ${reset}
   else 
      $ECHOCMD  $OK2audit Send files \"${file}.enc\" and \"${PHRASE}.enc\" to the auditor ${reset}
      $RMCMD    $PHRASE       ${file}                    > /dev/null 2>&1
   fi

else
   $ECHOCMD $bangred There was an error encrypting file \"${file}\" ...
   $ECHOCMD $bangred Please report error to auditor
   $RMCMD   $PHRASE                                    > /dev/null 2>&1
   exit 2
fi
exit 0
