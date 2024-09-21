#include <symmetric/aes.hpp>
#include <filesystem>
#include <exception>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <array>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>

AES::AES(std::filesystem::path key_path){
    try{
        if(!std::filesystem::exists(key_path)){
            throw std::string(key_path) + "do not exist";
        }
        std::string hexed_key;
        std::ifstream file_reader(key_path);
        file_reader >> hexed_key;
        auto key_stream = Botan::hex_decode(hexed_key);
        encrypter = Botan::Cipher_Mode::create_or_throw("AES-256/CBC", Botan::Cipher_Dir::Encryption);
        decrypter = Botan::Cipher_Mode::create("AES-256/CBC", Botan::Cipher_Dir::Decryption);
        encrypter->set_key(key_stream);
        decrypter->set_key(key_stream);
    }
    catch(const std::exception& e){
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

void AES::generateKey(std::filesystem::path key_path){
    try{
        key_path = key_path.lexically_normal();
        if(!std::filesystem::exists(key_path)){
            if(!std::filesystem::create_directories(key_path)){
                throw "file path conflict, please check";
            }
        }
        key_path = key_path / "id_aes";
        Botan::AutoSeeded_RNG rng;
        auto key_stream = rng.random_vec<std::vector<uint8_t>>(32);
        auto hex_key_stream = Botan::hex_encode(key_stream);
        std::ofstream file_writer(key_path);
        file_writer << std::string(hex_key_stream.begin(), hex_key_stream.end());
        file_writer.close();
    }
    catch(const std::exception& e){
        std::cerr << "exception caught: " << e.what() << std::endl;
        exit(1);
    }
}

std::string AES::encryptText(const std::string& unencrypted_str){
    Botan::AutoSeeded_RNG rng;
    auto iv = rng.random_vec<std::vector<uint8_t>>(16);
    std::vector<uint8_t> str_stream(unencrypted_str.data(), unencrypted_str.data() + unencrypted_str.length());
    encrypter->start(iv);
    encrypter->finish(str_stream);
    std::vector<uint8_t> cipher_with_vi;
    cipher_with_vi.insert(cipher_with_vi.end(), iv.begin(), iv.end());
    cipher_with_vi.insert(cipher_with_vi.end(), str_stream.begin(), str_stream.end());
    return std::string(cipher_with_vi.begin(), cipher_with_vi.end());
}

std::string AES::decryptText(const std::string& cipher_text){
    std::vector<uint8_t> str_stream(cipher_text.begin(), cipher_text.end());
    std::vector<uint8_t> iv(str_stream.begin(), str_stream.begin() + 16);
    std::vector<uint8_t> cipher(str_stream.begin() + 16, str_stream.end());
    decrypter->start(iv);
    decrypter->finish(cipher);
    return std::string(cipher.begin(), cipher.end());
}