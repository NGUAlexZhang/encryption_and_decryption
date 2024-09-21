#include <botan/hash.h>
#include <botan/hex.h>
#include <hash/sha.hpp>

namespace HASH{

    std::string plain2hash(const std::string& plain_text, const std::string& algo){
        auto hash_function = Botan::HashFunction::create_or_throw(algo);
        hash_function->update(plain_text);
        auto hash_stream = hash_function->final();
        return std::string(hash_stream.begin(), hash_stream.end());
    }
}