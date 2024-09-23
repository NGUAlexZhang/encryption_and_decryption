
#include <symmetric/aes.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <exception>
#include <fstream>

#include <utils/path_handler.hpp>


int main(int argc, char** argv){
    cxxopts::Options opt("az-aes", "generate aes key, encrypt/decrypt");
    opt.add_options()
    ("h,help", "Print Usage")
    ("f,file", "Key File Path", cxxopts::value<std::string>())
    ("o,output", "Output File Path", cxxopts::value<std::string>())
    ("e,encrypt", "Encrypt A Text File With Public Key", cxxopts::value<std::string>())
    ("d,decrypt", "Decrypt A Text File With Private Key", cxxopts::value<std::string>())
    ("g,generate", "Generate A RSA Key Pair");

    try{
        auto result = opt.parse(argc, argv);
        if(result.count("help")){
            std::cout << opt.help() << std::endl;
            return 0;
        }
        if(result.count("generate")){
            AES::generateKey();
            auto home_path = Path_Handler::getHomePath();
            std::cout << "The key output to " << home_path / ".az_rsa / id_aes" << std::endl;
            return 0;
        }
        if(!result.count("file")){
            throw std::invalid_argument("No Key File Input");
        }
        //std::cerr << result["file"].as<std::string>() << std::endl;
        std::string output;
        if(result.count("encrypt")){
            auto plain_text_path = result["encrypt"].as<std::string>();
            auto plain_text = Path_Handler::getFileString(plain_text_path);
            auto key_path = result["file"].as<std::string>();
            AES aes(key_path);
            output = aes.encryptText(plain_text);
        }
        else
        if(result.count("decrypt")){
            auto cipher_text_path = result["decrypt"].as<std::string>();
            auto cipher_text = Path_Handler::getFileString(cipher_text_path);
            auto key_path = result["file"].as<std::string>();
            AES aes(key_path);
            output = aes.decryptText(cipher_text);
        }
        if(result.count("output")){
            std::string output_path = result["output"].as<std::string>();
            std::ofstream file_writer(output_path);
            if(!file_writer.is_open()){
                throw std::invalid_argument("can\'t print text to " + output_path);
            }
            file_writer << output;
            file_writer.close();
        }
        else{
            std::cout << output << std::endl;
        }
    }
    catch(const std::exception& e){
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}