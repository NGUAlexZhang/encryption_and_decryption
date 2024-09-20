#include <filesystem>
#include <utils/path_handler.hpp>

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
}