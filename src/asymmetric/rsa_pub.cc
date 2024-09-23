
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/pem.h>
#include <botan/x509_key.h>

#include <asymmetric/rsa.hpp>
#include <filesystem>
#include <iostream>
#include <exception>
#include <fstream>
#include <cstdlib>
#include <utils/path_handler.hpp>


std::unique_ptr<Botan::Public_Key> RSA_pub::getPublicKeyDataSourceStream(const std::filesystem::path& public_key_path){
    auto public_key_str = Path_Handler::getFileString(public_key_path);
    //Botan::DataSource_Stream in(public_key_path_str);
    return Botan::X509::load_key(std::vector<uint8_t>(public_key_str.begin(), public_key_str.end()));
}
RSA_pub::RSA_pub(std::filesystem::path public_key_path) try:
    public_key(getPublicKeyDataSourceStream(public_key_path)){
    pk_verifier = std::make_unique<Botan::PK_Verifier>(*(this->public_key), "EMSA3(SHA-256)");
}
catch(const std::exception& e){
    std::cerr << "rsa.cc 72 Exception caught: " << e.what() << std::endl;
    throw e;
    exit(1);
}

std::string RSA_pub::encrypt_string(const std::string& plain_text){
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> vecpt(plain_text.data(), plain_text.data() + plain_text.length());
    Botan::PK_Encryptor_EME enc(*(this->public_key), rng, "OAEP(SHA-256)");
    auto encrypted = enc.encrypt(vecpt, rng);
    return std::string(encrypted.begin(), encrypted.end());
}

bool RSA_pub::verify_sign(const std::string& unsigned_str, std::string& sign){
    std::vector<uint8_t> sign_stream(sign.data(), sign.data() + sign.length());
    std::vector<uint8_t> unsigned_str_stream(unsigned_str.data(), unsigned_str.data() + unsigned_str.length());
    return this->pk_verifier->verify_message(unsigned_str_stream.data(), unsigned_str_stream.size(),
        sign_stream.data(), sign_stream.size()
    );
}