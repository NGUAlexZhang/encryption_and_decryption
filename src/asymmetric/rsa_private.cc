#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>

#include <asymmetric/rsa.hpp>
#include <filesystem>
#include <iostream>
#include <exception>
#include <fstream>
#include <cstdlib>
#include <utils/path_handler.hpp>



std::unique_ptr<Botan::Private_Key> RSA_private::getPrivateKeyDataSourceStream(const std::filesystem::path& private_key_path){
    auto private_key_str = Path_Handler::getFileString(private_key_path);
    //Botan::DataSource_Stream in(private_key_path_str);
    return Botan::PKCS8::load_key(std::vector<uint8_t>(private_key_str.begin(), private_key_str.end()));
}


RSA_private::RSA_private(std::filesystem::path private_key_path) try:
    private_key(getPrivateKeyDataSourceStream(private_key_path)){
        pk_signer = std::make_unique<Botan::PK_Signer>(*(this->private_key), this->rng, "EMSA3(SHA-256)");
}
catch(const std::exception& e){
    std::cerr << "rsa.cc 72 Exception caught: " << e.what() << std::endl;
    exit(1);
}

std::string RSA_private::decrypt_string(const std::string& cipher_text){
    Botan::PK_Decryptor_EME dec(*(this->private_key), this->rng, "OAEP(SHA-256)");
    std::vector<uint8_t> vecpt(cipher_text.data(), cipher_text.data() + cipher_text.length());
    auto decrypted = dec.decrypt(vecpt.data(), vecpt.size());
    return std::string(decrypted.begin(), decrypted.end());
}

std::string RSA_private::sign_string(const std::string& unsigned_str){
    std::vector<uint8_t> str_stream(unsigned_str.data(), unsigned_str.data() + unsigned_str.length());
    auto signed_string = this->pk_signer->sign_message(
        str_stream.data(), str_stream.size(), this->rng
    );
    return std::string(signed_string.begin(), signed_string.end());
}