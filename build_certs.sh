#!/bin/bash 
echo "export LICENSE_DAYS=\"-days <days>\" controls the licensing duration"
echo
export OPENSSL_CONF=./openssl.cnf
if [ ! -f LicensingCA/cacert.pem ]; then
    echo $'************************\n*** Generating ROOT CA ***' 
    /usr/lib/ssl/misc/CA.pl -newca
fi

echo -n $'************************\n*** Generating Client Certificate ***\n ' 
echo -n $'> '
read

/usr/lib/ssl/misc/CA.pl -newreq-nodes && /usr/lib/ssl/misc/CA.pl -sign && mv newcert.pem client.pem && mv newkey.pem client_key.pem && rm newreq.pem
