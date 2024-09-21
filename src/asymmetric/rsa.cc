#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/pem.h>
#include <botan/x509_key.h>

#include <asymmetric/ras.hpp>
#include <filesystem>
#include <iostream>
#include <exception>
#include <fstream>
#include <cstdlib>

void RSA::generate_key(std::filesystem::path key_pair_path){
    try{
        key_pair_path = key_pair_path.lexically_normal();
        if(!std::filesystem::exists(key_pair_path)){
            if(!std::filesystem::create_directories(key_pair_path)){
                throw "file path conflict, please check";
            }
        }
        Botan::AutoSeeded_RNG rng;         
        Botan::RSA_PrivateKey private_key(rng, 2048);
        Botan::RSA_PublicKey public_key(private_key);

        auto private_key_path = key_pair_path / "id_rsa";
        auto public_key_path = key_pair_path / "id_rsa.pub";

        std::ofstream file_writer(private_key_path);
        file_writer << Botan::PKCS8::PEM_encode(private_key);
        file_writer.close();

        file_writer.open(public_key_path);
        file_writer << Botan::X509::PEM_encode(public_key);
        file_writer.close();
    }
    catch(const std::exception& e){
        std::cerr << "rsa.cc 42 Exception caught: " << e.what() << std::endl;
        exit(1);
    }
}


std::unique_ptr<Botan::Private_Key> RSA::getPrivateKeyDataSourceStream(const std::filesystem::path& private_key_path){
    if(!std::filesystem::exists(private_key_path)){
        throw std::string(private_key_path) + "do not exist";
    }
    auto private_key_path_str = std::string(private_key_path);
    Botan::DataSource_Stream in(private_key_path_str);
    return Botan::PKCS8::load_key(in);
}

std::unique_ptr<Botan::Public_Key> RSA::getPublicKeyDataSourceStream(const std::filesystem::path& public_key_path){
    if(!std::filesystem::exists(public_key_path)){
        throw std::string(public_key_path) + "do not exist";
    }
    auto public_key_path_str = std::string(public_key_path);
    Botan::DataSource_Stream in(public_key_path_str);
    return Botan::X509::load_key(in);
}
RSA::RSA(std::filesystem::path private_key_path, std::filesystem::path public_key_path) try:
    private_key(getPrivateKeyDataSourceStream(private_key_path)), 
    public_key(getPublicKeyDataSourceStream(public_key_path)){
        pk_signer = std::make_unique<Botan::PK_Signer>(*(this->private_key), this->rng, "EMSA3(SHA-256)");
}
catch(const std::exception& e){
    std::cerr << "rsa.cc 72 Exception caught: " << e.what() << std::endl;
    exit(1);
}

std::string RSA::encrypt_string(const std::string& plain_text){
    std::vector<uint8_t> vecpt(plain_text.data(), plain_text.data() + plain_text.length());
    Botan::PK_Encryptor_EME enc(*(this->public_key), this->rng, "OAEP(SHA-256)");
    auto encrypted = enc.encrypt(vecpt, this->rng);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string RSA::decrypt_string(const std::string& cipher_text){
    Botan::PK_Decryptor_EME dec(*(this->private_key), this->rng, "OAEP(SHA-256)");
    std::vector<uint8_t> vecpt(cipher_text.data(), cipher_text.data() + cipher_text.length());
    auto decrypted = dec.decrypt(vecpt.data(), vecpt.size());
    return std::string(decrypted.begin(), decrypted.end());
}

std::string RSA::sign_string(const std::string& unsigned_str){
    std::vector<uint8_t> str_stream(unsigned_str.data(), unsigned_str.data() + unsigned_str.length());
    auto signed_string = this->pk_signer->sign_message(
        str_stream.data(), str_stream.size(), this->rng
    );
    return std::string(signed_string.begin(), signed_string.end());
}