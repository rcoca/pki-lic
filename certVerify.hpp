/**************************************************************************
** File: certVerify.hpp
** Created: 10.07.2015
** Author:  razvan  (nrexp.office@gmail.com)
**
**************************************************************************/
#include <string>
#include <sstream>
#ifndef CERTVERIFY
#define CERTVERIFY
void initLicensing();
void cleanupLicensing();
bool certVerifyString(std::string const& certificate, std::string const& ca_certificate,std::ostringstream& log);
bool certVerifyFile(std::string const& cert_file_name,std::string const& ca_certificate,std::ostringstream& log);
#endif // CERTVERIFY

