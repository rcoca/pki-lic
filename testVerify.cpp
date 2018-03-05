/**************************************************************************
** File:testVerify.cpp
** Created: 10.07.2015
** Author:  razvan  (nrexp.office@gmail.com)
** program to check license certificates verification
**
**************************************************************************/

#include "caCertificate.hpp"
#include "xClientCertificate.hpp"
#include <iostream>
#include "certVerify.hpp"

int main(int argc, char* argv[])
{
    if(argc<2)
    {
        std::clog<<"Error: no valid command line provided: usage: "<<argv[0]<<" client_cert_file.pem"<<std::endl;
        return -1;
    }


    initLicensing();
    std::clog<<"App verification: ";
    std::ostringstream os;
    if(!certVerifyString(xClientCertificate,caCertificate,os))
    {
        std::clog<<os.str()<<std::endl;
    }
    else std::clog<<"... OK"<<std::endl;

    os.str("");
    std::clog<<std::endl;
    std::clog<<"File verification: ";
    if(!certVerifyFile(argv[1],caCertificate,os))
    {
        std::clog<<os.str()<<std::endl;
    }
    else  std::clog<<"... OK"<<std::endl;
    cleanupLicensing();

    return 0;
}


