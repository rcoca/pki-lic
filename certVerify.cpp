/**************************************************************************
** File: certVerify.cpp
** Created: 10.07.2015
** Author:  razvan  (nrexp.office@gmail.com)
**
**************************************************************************/

#include <string>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <sstream>

#include "certVerify.hpp"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <vector>

static bool initialized_licensing=false;

template<typename handler_t>
struct ScopeExitCallback
{
    ScopeExitCallback(handler_t&& Handler):handler(Handler){}
    ~ScopeExitCallback()
    {
        try
        {
            handler();
        }
        catch(...){
            std::clog<<"Error cleaning up at scope exit: file"
                    <<__FILE__<<" line: "<<__LINE__<<std::endl;
        }
    }

private:
    handler_t handler;
};

template<typename handler_t>
ScopeExitCallback<handler_t> ScopeExit(handler_t&& Handler)
{
    return ScopeExitCallback<handler_t>(std::forward<handler_t>(Handler));
}

void initLicensing()
{

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();    
    ERR_load_crypto_strings();
    initialized_licensing=true;
}
void cleanupLicensing()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();
    CRYPTO_mem_leaks_fp(stderr);
    initialized_licensing=false;
}
X509* loadCertString(std::string const& cert_string)
{
    BIO *bio=BIO_new(BIO_s_mem());
    auto bioclean=ScopeExit([&](){if(bio)BIO_free(bio);});
    BIO_puts(bio,cert_string.c_str());
    X509* certificate = PEM_read_bio_X509(bio, NULL, 0, NULL);
    return certificate;
}

X509_STORE* loadCaStore(std::string const& ca_certificate)
{
    X509_STORE* store=nullptr;
    X509* certificate = loadCertString(ca_certificate);
    if(certificate==nullptr)
        throw std::runtime_error("Not a valid CA certificate: "+ ca_certificate);
    store=X509_STORE_new();
    int result=0;
    if(! (result=X509_STORE_add_cert(store,certificate)))
            throw std::runtime_error("Provisioning cert store with CA cert returned: "+std::to_string(result));
    return store;
}

bool certVerifyString(std::string const& certificate, std::string const& ca_certificate, std::ostringstream &log)
{

    if(!initialized_licensing)   initLicensing();
    int retcode=0;
    try
    {
        X509* client_certificate  = loadCertString(certificate);
        auto cert_cleanup        = ScopeExit([&](){
            if(client_certificate) X509_free(client_certificate);
            client_certificate=nullptr;
        });
        if(client_certificate==nullptr)
            throw std::runtime_error("Invalid LICENSE certificate: "+certificate);

        X509_STORE * store       = loadCaStore(ca_certificate);
        auto store_cleanup       = ScopeExit([&](){
            if(store) X509_STORE_free(store);
            store=nullptr;
        });

        X509_STORE_CTX  *vrfy_ctx = X509_STORE_CTX_new();
        auto context_cleanup      = ScopeExit([&](){
            if(vrfy_ctx) X509_STORE_CTX_free(vrfy_ctx);
            vrfy_ctx=nullptr;
        });
        X509_STORE_CTX_init(vrfy_ctx, store, client_certificate, NULL);
        X509_STORE_CTX_set_flags(vrfy_ctx,X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_POLICY_CHECK);       
        retcode = X509_verify_cert(vrfy_ctx);
        long err =   X509_STORE_CTX_get_error(vrfy_ctx);
        long depth = X509_STORE_CTX_get_error_depth(vrfy_ctx);



        std::string verification_message(X509_verify_cert_error_string(err));

        log<<verification_message<<std::endl;
        if(retcode==0)
        {
            X509*        error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
            auto   certsubject = X509_get_subject_name(error_cert);            
            BIO *outbio=BIO_new(BIO_s_mem());            
            auto bio_cleanup         = ScopeExit([&](){BIO_free(outbio);});

            X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
            BIO_printf(outbio,"\n");
            X509_NAME_print_ex(outbio, X509_get_issuer_name(error_cert), 0, XN_FLAG_ONELINE);
            BIO_printf(outbio,"\n");
            BIO_printf(outbio,"notBefore=");
            ASN1_TIME_print(outbio,X509_get_notBefore(error_cert));
            BIO_printf(outbio,"\n");
            BIO_printf(outbio,"notAfter=");
            ASN1_TIME_print(outbio,X509_get_notAfter(error_cert));
            BIO_printf(outbio,"\n");
            BIO_printf(outbio,"verify error:num=%ld:%s, depth=%ld\n",err,X509_verify_cert_error_string(err),depth);
            std::size_t N=BIO_number_written(outbio);
            std::vector<char> buffer(N+1,'\0');
            BIO_read(outbio,&buffer[0],N);
            std::string s(buffer.begin(),buffer.end());
            log<<s<<std::endl;
        }

    }
    catch(std::exception const& e)
    {
        log<<"Error:"<<std::endl;
        log<<e.what()<<std::endl;
        return false;
    }
    return retcode==1;
}
bool certVerifyFile(std::string const& cert_file_name,std::string const& ca_certificate,std::ostringstream &log)
{
    if(!initialized_licensing)   initLicensing();
    try
    {
        std::string s;
        {
            std::ifstream cert_file(cert_file_name);
            if(!cert_file.is_open())
                throw std::runtime_error("Cannot open file: "+cert_file_name);
            std::ostringstream ss;
            ss << cert_file.rdbuf();
            s = ss.str();
        }
        return certVerifyString(s,ca_certificate,log);
    }
    catch(std::runtime_error const& e)
    {
        log<<"Error:"<<std::endl;
        log<<e.what()<<std::endl;
        return false;
    }
    return false;
}
