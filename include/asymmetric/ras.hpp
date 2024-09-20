#ifndef __RSA__HPP
#define __RSA__HPP

#include <filesystem>
#include <utils/path_handler.hpp>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>

static auto home_path = Path_Handler::getHomePath();
class RSA{
protected:
    std::unique_ptr<Botan::Private_Key> private_key;
    std::unique_ptr<Botan::Public_Key> public_key;
    
    std::unique_ptr<Botan::Private_Key> getPrivateKeyDataSourceStream(const std::filesystem::path& private_key_path);
    std::unique_ptr<Botan::Public_Key> getPublicKeyDataSourceStream(const std::filesystem::path& public_key_path);

public:
    RSA(std::filesystem::path private_key_path = home_path / "./.az_rsa/id_rsa",
        std::filesystem::path public_key_path = home_path / "./.az_rsa/id_rsa.pub");
    static void generate_key(std::filesystem::path key_pair_path = home_path / "./.az_rsa");
    std::vector<uint8_t> encrypt_string(std::string plain_text);
    std::string decrypt_string(std::vector<uint8_t> cipher_text);
    
};

#endif