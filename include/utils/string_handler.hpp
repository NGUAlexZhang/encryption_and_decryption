#include <string>
#include <vector>
#include <cstdint>

std::vector<uint8_t>&& string2vec_uint8_t(const std::string& str);
std::string&& vec_uint8_t2string(const std::vector<uint8_t> vec_stream);