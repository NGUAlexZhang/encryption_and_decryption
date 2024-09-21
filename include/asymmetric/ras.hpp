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
    std::unique_ptr<Botan::PK_Signer> pk_signer;
    std::unique_ptr<Botan::PK_Verifier> pk_verifier;
    Botan::AutoSeeded_RNG rng; 
    std::unique_ptr<Botan::Private_Key> getPrivateKeyDataSourceStream(const std::filesystem::path& private_key_path);
    std::unique_ptr<Botan::Public_Key> getPublicKeyDataSourceStream(const std::filesystem::path& public_key_path);

public:
    RSA(std::filesystem::path private_key_path = home_path / "./.az_rsa/id_rsa",
        std::filesystem::path public_key_path = home_path / "./.az_rsa/id_rsa.pub");
    static void generate_key(std::filesystem::path key_pair_path = home_path / "./.az_rsa");
    std::string encrypt_string(const std::string& plain_text);
    std::string decrypt_string(const std::string& cipher_text);
    std::string sign_string(const std::string& unsigned_str);
    bool verify_sign(const std::string& unsigned_str, std::string& sign);
    
};

#endif