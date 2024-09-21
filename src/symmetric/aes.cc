#include <symmetric/aes.hpp>
#include <filesystem>
#include <exception>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>

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
        std::vector<uint8_t> key_stream; 
        rng.random_vec(key_stream);
        auto hex_key_stream = Botan::hex_encode(key_stream);
        for(auto ch : key_stream){
            std::cerr << ch << " ";
        }
        std::cerr << std::endl;
        std::ofstream file_writer(key_path);
        file_writer << std::string(hex_key_stream.begin(), hex_key_stream.end());
        file_writer.close();
    }
    catch(const std::exception& e){
        std::cerr << "exception caught: " << e.what() << std::endl;
        exit(1);
    }
}