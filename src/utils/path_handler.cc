#include <string>
#include <filesystem>
#include <utils/path_handler.hpp>
#include <exception>
#include <fstream>

namespace Path_Handler{
    std::filesystem::path getHomePath(){
        return std::filesystem::path(
            #ifdef _WIN32
                std::getenv("USERPROFILE")
            #else
                std::getenv("HOME")
            #endif
        );
    }

    std::string getFileString(const std::filesystem::path& file_path){
        if(!std::filesystem::exists(file_path)){
            throw std::invalid_argument(std::string(file_path) + "do not exist");
        }
        if(std::filesystem::is_directory(file_path)){
            throw std::invalid_argument(std::string(file_path) + "is a directory");
        }
        auto file_path_str = std::string(file_path);
        std::ifstream file_reader(file_path_str);
        if(!file_reader.is_open()){
            throw std::invalid_argument("can not open" + std::string(file_path));
        }
        std::stringstream buffer;
        buffer << file_reader.rdbuf();
        file_reader.close();
        return buffer.str();
    }
}