#ifndef __SHA__HPP
#define __SHA__HPP
#include <string_view>
#include <string>
namespace HASH{
    std::string plain2hash(const std::string& plain_text, const std::string& algo = "SHA-256");
};
#endif