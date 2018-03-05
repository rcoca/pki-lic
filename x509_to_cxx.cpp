/**************************************************************************
** File: x509_to_cxx.cpp
** Created: 10.07.2015
** Author:  razvan  (nrexp.office@gmail.com)
**
** Utility to transform a digital certificate in a code variable.
** Good for licensing software based on certificate expiration date
**
**************************************************************************/
#include <fstream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iostream>

std::string doHeader(std::string const& var_name)
{
    std::ostringstream os;
    os<<"#include <string>"<<std::endl
      <<"#ifndef LICENSE_ONCE_"<<var_name<<std::endl
      <<"#define LICENSE_ONCE_"<<var_name<<std::endl
      <<"extern std::string "<<var_name<<";"<<std::endl
    <<"#endif // LICENSE_ONCE_"<<var_name<<std::endl;
    return os.str();
}

std::string doCode(std::string const& var_name)
{
    std::ostringstream os;
    os<<"#include <string>"<<std::endl
      <<"std::string "<<var_name<<" = ";
    return os.str();
}

void certTranslateToCode(std::string const& cert_file_name,std::string const& var_name, bool debug=true)
{
    {
        std::ofstream header_file(var_name+".hpp");
        if(!header_file.is_open())
            throw std::runtime_error("Could not open file: "+var_name+".hpp");
        header_file<<doHeader(var_name);
    }
    std::ofstream code_file(var_name+".cpp");
    if(!code_file.is_open())
        throw std::runtime_error("Could not open file: "+var_name+".hpp");

    std::ifstream cert_file(cert_file_name);
    if(!cert_file.is_open())
        throw std::runtime_error("Could not open file: "+cert_file_name);
    code_file<<doCode(var_name);
    std::string line;
    if(debug)
    {
        while(std::getline(cert_file, line))
            code_file<<'"'<<line<<"\\n"<<'"'<<std::endl;
        code_file<<";"<<std::endl;
    }
    else
    {
        bool started=false;
        while(std::getline(cert_file, line))
        {
            if(line=="-----BEGIN CERTIFICATE-----")
                started=true;
            if(started)
                code_file<<'"'<<line<<"\\n"<<'"'<<std::endl;
        }
        code_file<<";"<<std::endl;
    }
}

int main(int argc, char *argv[])
{
    if(argc<3)
    {
        std::clog<<"Error: no valid command line provided: usage: "<<argv[0]<<" cert_file.pem cpp_name"<<std::endl;
        return -1;
    }
    try
    {
        bool debug=false;
        char* env_debug=getenv("debug");
        if(env_debug)
        {
            debug=std::atoi(env_debug);
            if(debug)
                std::clog<<"Proceeding in debug mode with verbose certificates as instructed : "<<env_debug<<std::endl;
        }
        certTranslateToCode(argv[1],argv[2],debug);
        std::clog<<argv[1]<<" was translated into C++, variable name: std::string "<<argv[2]<<std::endl;
    }
    catch(std::exception const& e)
    {
        std::clog<<"Error: "<<e.what()<<std::endl;
        return -2;
    }
}
