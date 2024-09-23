#ifndef __PATH_HANDLER__HPP
#define __PATH_HANDLER__HPP
#include <filesystem>
#include <string>

namespace Path_Handler{
    std::filesystem::path getHomePath();
    std::string getFileString(const std::filesystem::path& file_path);
}

#endif