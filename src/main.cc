#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>

#include <asymmetric/ras.hpp>

int main() {
    RSA rsa;
    auto vecpt = rsa.encrypt_string("Hello motherfucker");
    std::string str(vecpt.begin(), vecpt.end());
    std::cerr << str << std::endl;
    std::cerr << rsa.decrypt_string(str) << std::endl;
    auto kkk = rsa.sign_string("Hello fucker");
    std::cerr << kkk << std::endl;
    std::cerr << rsa.verify_sign("Hello fucker", kkk);
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
