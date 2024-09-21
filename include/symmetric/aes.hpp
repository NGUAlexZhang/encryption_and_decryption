#ifndef __AES__HPP
#define __AES__HPP
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <utils/path_handler.hpp>


class AES{
protected:
    std::unique_ptr<Botan::Cipher_Mode> encrypter;
    std::unique_ptr<Botan::Cipher_Mode> decrypter;
public:
    AES(std::filesystem::path key_path = Path_Handler::getHomePath() / ".az_rsa/id_aes");
    static void generateKey(std::filesystem::path key_path = Path_Handler::getHomePath() / ".az_rsa");
    std::string encryptText(const std::string& unencrypted_str);
    std::string decryptText(const std::string& cipher_text);

};

#endif