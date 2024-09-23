#include <asymmetric/rsa.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <exception>
#include <fstream>

#include <utils/path_handler.hpp>


int main(int argc, char** argv){
    cxxopts::Options opt("az-rsa", "generate rsa keys, encrypt/decrypt and sign/verify");
    opt.add_options()
    ("h,help", "Print Usage")
    ("f,file", "Key File Path", cxxopts::value<std::string>())
    ("o,output", "Output File Path", cxxopts::value<std::string>())
    ("e,encrypt", "Encrypt A Text File With Public Key", cxxopts::value<std::string>())
    ("d,decrypt", "Decrypt A Text File With Private Key", cxxopts::value<std::string>())
    ("s,sign", "Sign A Text File With Private Key", cxxopts::value<std::string>())
    ("v,verify", "Verify A Text File With Public Key", cxxopts::value<std::string>())
    ("p,plain", "plain text for verify sign", cxxopts::value<std::string>())
    ("g,generate", "Generate A RSA Key Pair");

    try{
        auto result = opt.parse(argc, argv);
        if(result.count("help")){
            std::cout << opt.help() << std::endl;
            return 0;
        }
        if(result.count("generate")){
            RSA::generateKey();
            auto home_path = Path_Handler::getHomePath();
            std::cout << "The pair output to " << home_path / ".az_rsa" << " folder" << std::endl;
            std::cout << "file \"id_rsa\" is private key and file \"id_rsa.pub\" is public key" << std::endl;
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
            RSA_pub rsa_pub(key_path);
            output = rsa_pub.encrypt_string(plain_text);
        }
        else
        if(result.count("decrypt")){
            auto cipher_text_path = result["decrypt"].as<std::string>();
            auto cipher_text = Path_Handler::getFileString(cipher_text_path);
            auto key_path = result["file"].as<std::string>();
            RSA_private rsa_private(key_path);
            output = rsa_private.decrypt_string(cipher_text);
        }
        else
        if(result.count("sign")){
            auto plain_text_path = result["sign"].as<std::string>();
            auto plain_text = Path_Handler::getFileString(plain_text_path);
            auto key_path = result["file"].as<std::string>();
            RSA_private rsa_private(key_path);
            output = rsa_private.sign_string(plain_text);
        }
        else{
            if(!result.count("plain")){
                throw std::invalid_argument("No plain text file input");
            }
            auto signed_text_path = result["verify"].as<std::string>();
            auto signed_text = Path_Handler::getFileString(signed_text_path);
            auto plain_text_path = result["plain"].as<std::string>();
            auto plain_text = Path_Handler::getFileString(plain_text_path);
            auto key_path = result["file"].as<std::string>();
            RSA_pub rsa_pub(key_path);
            auto passed = rsa_pub.verify_sign(plain_text, signed_text);
            if(passed){
                output = "Verify pass";
            }
            else output = "Verify don\'t pass";
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