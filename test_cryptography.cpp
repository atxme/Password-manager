#include "cryptography_V2.hpp"

using namespace cryptography;


int main() {
    // Générer une paire de clés elliptiques
    EC_KEY* privateKey;
    EC_POINT* publicKey;
    cryptography::encryption::EllipticCurve ec;
    ec.GENERATE_EC_KEYPAIR(privateKey, publicKey);

    // Le texte clair à chiffrer
    std::string plaintext = "Ceci est un message secret.";

    // Chiffrer le message avec la clé publique
    std::string encryptedMessage = ec.encrypt(plaintext, publicKey);

    // Afficher le message chiffré en base64
    std::string encryptedMessageBase64 = cryptography::binaryToBase64(encryptedMessage);
    std::cout << "Message chiffré (base64) : " << encryptedMessageBase64 << std::endl;

    // Déchiffrer le message avec la clé privée
    std::string decryptedMessage = ec.decrypt(encryptedMessage, privateKey);

    // Afficher le message déchiffré en base64
    std::string decryptedMessageBase64 = cryptography::binaryToBase64(decryptedMessage);
    std::cout << "Message déchiffré (base64) : " << decryptedMessageBase64 << std::endl;

    // Libérer la mémoire allouée pour les clés
    EC_KEY_free(privateKey);

    return 0;
}