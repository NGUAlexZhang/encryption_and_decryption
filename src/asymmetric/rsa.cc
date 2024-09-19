#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/pem.h>

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
        auto public_key_der = public_key.subject_public_key();
        file_writer << Botan::PEM_Code::encode(public_key_der.data(), public_key_der.size(), "PUBLIC KEY", 64);
        file_writer.close();
    }
    catch(const std::exception& e){
        std::cerr << "Exception caught: " << e.what() << std::endl;
        exit(1);
    }
}