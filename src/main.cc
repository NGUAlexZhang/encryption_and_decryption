#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>

#include <asymmetric/rsa.hpp>
#include <symmetric/aes.hpp>
#include <hash/sha.hpp>

int main() {
    //RSA_pub rsa_pub;
    //RSA_private rsa_private;
    //auto enc = rsa_pub.encrypt_string("Hello motherfxxker");
    //std::cerr << enc << std::endl;
    //std::cerr << rsa_private.decrypt_string(enc) << std::endl;

    //auto sign = rsa_private.sign_string("I'm your father");
    //std::cerr << sign << std::endl;
    //std::cerr << rsa_pub.verify_sign("I'm your fathe", sign);
//    AES::generateKey();
    AES aes;
    auto cipher = aes.encryptText("1234567");
    std::cerr << cipher << std::endl;
    std::cerr << aes.decryptText(cipher);
    auto hash_str = HASH::plain2hash("12321", "SHA-256");
    std::vector<uint8_t> hash_stream(hash_str.begin(), hash_str.end());
//    std::cerr << Botan::hex_encode(HASH::plain2hash("12321", "SHA-256"));
    std::cerr << Botan::hex_encode(hash_stream) << std::endl;
    //try {
    //    // Initialize random number generator
    //    Botan::AutoSeeded_RNG rng;

    //    // Generate RSA key pair (2048-bit)
    //    Botan::RSA_PrivateKey private_key(rng, 2048);
    //    Botan::RSA_PublicKey public_key(private_key);

    //    // Message to encrypt
    //    std::string message = "Hello, RSA encryption using Botan 3!";

    //    // Encrypt the message using the public key
    //    Botan::PK_Encryptor_EME encryptor(public_key, rng, "OAEP(SHA-256)");
    //    std::vector<uint8_t> ciphertext = encryptor.encrypt(
    //        reinterpret_cast<const uint8_t*>(message.data()), message.size(), rng);

    //    // Display the encrypted message in hex format
    //    std::cout << "Encrypted message: " << Botan::hex_encode(ciphertext) << std::endl;

    //    // Decrypt the message using the private key
    //    Botan::PK_Decryptor_EME decryptor(private_key, rng, "OAEP(SHA-256)");
    //    Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(ciphertext.data(), ciphertext.size());

    //    // Convert decrypted data to string
    //    std::string decrypted_message(decrypted.begin(), decrypted.end());

    //    // Display the decrypted message
    //    std::cout << "Decrypted message: " << decrypted_message << std::endl;
    //} catch (const std::exception& e) {
    //    std::cerr << "Error: " << e.what() << std::endl;
    //}

    return 0;
}
