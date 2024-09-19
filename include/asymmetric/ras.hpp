#ifndef __RSA__HPP
#define __RSA__HPP

#include <filesystem>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>

class RSA{
private:
    Botan::RSA_PrivateKey private_key;
    Botan::RSA_PublicKey public_key;

public:
    RSA(std::string private_key_path, std::string public_key_path);
    static void generate_key(std::filesystem::path key_pair_path = std::filesystem::path(
        #ifdef _WIN32
            std::getenv("USERPROFILE")
        #else
            std::getenv("HOME")
        #endif
    )  / "./.az_rsa");
    std::string encpryt_string(std::string plain_text);
    std::string decpryt_string(std::string cipher_text);
};

#endif