#include "cryptography_V2.hpp"
#include <iostream>
#include <string>
#include <chrono>

using namespace cryptography;

void cryptageelliptique() {
    // Générer une paire de clés elliptiques
    EC_KEY* privateKey;
    EC_POINT* publicKey;
    cryptography::encryption::EllipticCurve ec;
    ec.GENERATE_EC_KEYPAIR(privateKey, publicKey);

    // Le texte clair à chiffrer
    std::string plaintext = "Ceci est un message secret.";
    std::cout << "Message en clair : " << plaintext << std::endl;
    // Chiffrer le message avec la clé publique
    std::string encryptedMessage = ec.encrypt(plaintext, publicKey);

    // Afficher le message chiffré en base64
    std::string encryptedMessageBase64 = cryptography::binaryToBase64(encryptedMessage);
    std::cout << "Message chiffré (base64) : " << encryptedMessageBase64 << std::endl;

    // Déchiffrer le message avec la clé privée
    std::string decryptedMessage = ec.decrypt(encryptedMessage, privateKey);
     std::cout << "Message déchiffré : " << decryptedMessage << std::endl;
    // Libérer la mémoire allouée pour les clés
    EC_KEY_free(privateKey);

}

void cryptageRsa() {
    // Générer une paire de clés RSA
    int key_length = 8096;
    std::string public_key_str, private_key_str;
    cryptography::encryption::RSAEncryption::generateRSAKeyPair(key_length, public_key_str, private_key_str);

    // Convertir les clés en structures RSA
    BIO* pub_key_bio = BIO_new_mem_buf(public_key_str.data(), -1);
    BIO* priv_key_bio = BIO_new_mem_buf(private_key_str.data(), -1);
    EVP_PKEY* evp_pkey = PEM_read_bio_PUBKEY(pub_key_bio, NULL, NULL, NULL);
    RSA* public_key = EVP_PKEY_get1_RSA(evp_pkey);
    RSA* private_key = PEM_read_bio_RSAPrivateKey(priv_key_bio, NULL, NULL, NULL);

    // Message en clair à chiffrer
    std::string plaintext = "Ceci est un message secret.";

    // Chiffrer le message en clair
    std::string encrypted_message_base64 = cryptography::binaryToBase64(cryptography::encryption::RSAEncryption::encrypt(plaintext, public_key));

    std::cout << "Message chiffré (base64) : " << encrypted_message_base64 << std::endl;

    // Déchiffrer le message chiffré
    std::string decrypted_message = cryptography::encryption::RSAEncryption::decrypt(encrypted_message_base64, private_key);


    std::cout << "Message déchiffré : " << decrypted_message << std::endl;

    // Libérer les structures RSA, EVP_PKEY et BIO
    RSA_free(public_key);
    RSA_free(private_key);
    EVP_PKEY_free(evp_pkey);
    BIO_free(pub_key_bio);
    BIO_free(priv_key_bio);
}



void cryptageAes(){

    // Générer une clé AES et un IV
    std::string aes_key, aes_iv;
    cryptography::encryption::AES::GENERATE_AES_KEY(aes_key);
    cryptography::encryption::AES::GENERATE_AES_IV(aes_iv);

    // Message en clair à chiffrer
    std::string plaintext = "J'aime les pattes";

    // Chiffrer le message en clair
    std::string encrypted_message;
    cryptography::encryption::AES::AES_ENCRYPTION(plaintext, aes_key, aes_iv, encrypted_message);

    // Déchiffrer le message chiffré
    std::string decrypted_message;
    cryptography::encryption::AES::AES_DECRYPTION(encrypted_message, aes_key, decrypted_message);

    // Afficher les résultats
    std::cout << "Message clair : " << plaintext << std::endl;
    std::cout << "Message chiffré (base64) : " << cryptography::binaryToBase64(encrypted_message) << std::endl;
    std::cout << "Message déchiffré : " << decrypted_message << std::endl;
}

void cryptageSha256(){
    // Message en clair à hacher
    std::string plaintext = "J'aime les pattes";

    // Hacher le message en clair
    std::string hashed_message = cryptography::HashFunctions::hash_SHA256(plaintext);

    // Afficher les résultats
    std::cout << "Message clair : " << plaintext << std::endl;
    std::cout << "Message haché (base64) : " << cryptography::binaryToBase64(hashed_message) << std::endl;
}

void cryptageSha512(){
    // Message en clair à hacher
    std::string plaintext = "J'aime les pattes";

    // Hacher le message en clair
    std::string hashed_message = cryptography::HashFunctions::hash_SHA512(plaintext);

    // Afficher les résultats
    std::cout << "Message clair : " << plaintext << std::endl;
    std::cout << "Message haché (base64) : " << cryptography::binaryToBase64(hashed_message) << std::endl;
}

template <typename Func>
void measureExecutionTime(Func&& func, const std::string& functionName) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "Temps d'exécution de la fonction " << functionName << " : " << duration << " microsecondes" << std::endl;
}

int main() {
    measureExecutionTime(cryptageelliptique, "Cryptage elliptique");
    measureExecutionTime(cryptageRsa, "Cryptage RSA");
    measureExecutionTime(cryptageAes, "Cryptage AES");
    measureExecutionTime(cryptageSha256, "Cryptage SHA256");
    measureExecutionTime(cryptageSha512, "Cryptage SHA512");

    return 0;
}