#include <hash/sha.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <exception>
#include <fstream>
#include <botan/hex.h>

#include <utils/path_handler.hpp>


int main(int argc, char** argv){
    cxxopts::Options opt("az-sha", "generate aes key, encrypt/decrypt");
    opt.add_options()
    ("h,help", "Print Usage")
    ("f,file", "Plain Text File Path", cxxopts::value<std::string>())
    ("a,algorithm", "Select A SHA Algotrithm, Such As SHA-256, SHA-512, SHA-224 And So On")
    ("o,output", "Output File Path", cxxopts::value<std::string>());

    try{
        auto result = opt.parse(argc, argv);
        if(result.count("help")){
            std::cout << opt.help() << std::endl;
            return 0;
        }
        if(!result.count("file")){
            throw std::invalid_argument("No File Input");
        }
        auto plain_path = result["file"].as<std::string>();
        auto plain_text = Path_Handler::getFileString(plain_path);
        std::string algo;
        if(!result.count("algorithm")){
            algo = "SHA-256";
        }
        else{
            algo = result["algorithm"].as<std::string>();
        }
        
        std::string output;
        output = HASH::plain2hash(plain_text, algo);
        output = Botan::hex_encode(std::vector<uint8_t>(output.begin(), output.end()));
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