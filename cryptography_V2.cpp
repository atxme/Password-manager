/*
||---------------------------------------------------------------------------------------------||
||---------------------------------------------------------------------------------------------||
||                                                                                             ||
|| This software is provided "as is" without warranty of any kind, either express or implied.  || 
||  The author of the software is not responsible for any damage caused by the software.       ||
||                                                                                             ||
||  You are not authorized to use this software without the agreement of the author.           || 
||                                                                                             ||    
||  This software uses the openssl library with renforced cryptography algorithms.             ||
||  If you change any codeline, the autor is not responsable                                   ||
||                                                                                             ||
||   ";)/""                                                                                    ||
||---------------------------------------------------------------------------------------------||
||---------------------------------------------------------------------------------------------||
*/

#ifndef __include_IOStream_h__
#define __include_IOStream_h__
#include <iostream>
#endif

#ifndef __include_vector_h__
#define __include_vector_h__
#include <vector>
#endif

#ifndef __include_string__
#define __include_string__
#include <string.h>
#endif

#ifndef __include_AES_h__
#define __include_AES_h__
#include <openssl/aes.h>
#endif

#ifndef __include_evp_h__
#define __include_evp_h__
#include <openssl/evp.h>
#endif

#ifndef __include_rand_h__
#define __include_rand_h__
#include <openssl/rand.h>
#endif

#ifndef __include_sha_h__
#define __include_sha_h__
#include <openssl/sha.h>
#endif

#ifndef __include_rsa_h__
#define __include_rsa_h__
#include <openssl/rsa.h>
#endif
#ifndef __include_ec_h__
#define __include_ec_h__
#include <openssl/ec.h>
#endif  

#ifndef __include_pem_h__
#define __include_pem_h__
#include <openssl/pem.h>
#endif

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __define_aes_size__ 
#define AES_KEY_SIZE 256
#define AES_KEY_LENGTH 256
#endif 

#ifndef __include_iomanip__
#define __include_iomanip__
#include <iomanip>
#endif

#ifndef __include_cstdlib__
#define __include_cstdlib__
#include <cstdlib>
#endif

#ifndef __include_stat__
#define __include_stat__
#include <sys/stat.h>
#endif

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __include_filesystem__
#define __include_filesystem__
#include <filesystem>
#endif

#ifndef __include_cryptography__
#define __include_cryptography__
#include "cryptography.hpp"
#endif

#ifndef __include_bitset__
#define __include_bitset__
#include <bitset>
#endif

#ifndef __include_obj_mac.h__
#define __include_obj_mac.h__
#include <openssl/obj_mac.h>
#endif

#ifndef __include_bn_h__
#define __include_bn_h__
#include <openssl/bn.h>
#endif

#include<openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/err.h>


#include "cryptography_V2.hpp"

namespace cryptography {

   
    template <typename T>
    std::string to_binary(const T& data)
    {
        std::string binary_str;
        const char* data_ptr = reinterpret_cast<const char*>(&data);
        const size_t data_size = sizeof(data);
        for (size_t i = 0; i < data_size; ++i) {
            std::bitset<8> binary_char(data_ptr[i]);
            binary_str += binary_char.to_string();
        }
        return binary_str;
    }

    std::string base64ToBinary(const std::string &base64_str) {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO *bio = BIO_new_mem_buf(base64_str.data(), -1);
        bio = BIO_push(b64, bio);

        std::vector<uint8_t> binary;
        ssize_t decoded_size;
        uint8_t buffer[512];
        while ((decoded_size = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
            binary.insert(binary.end(), buffer, buffer + decoded_size);
        }

        BIO_free_all(bio);
        return std::string(binary.begin(), binary.end());
    }

    std::string binaryToBase64(const std::string& binary_str) {
        // Créer un objet BIO en mémoire pour stocker le résultat en base64
        BIO* bio_base64 = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

        BIO* bio_mem = BIO_new(BIO_s_mem());
        bio_base64 = BIO_push(bio_base64, bio_mem);

        // Écrire la chaîne binaire dans l'objet BIO en base64
        BIO_write(bio_base64, binary_str.data(), binary_str.size());
        BIO_flush(bio_base64);

        // Récupérer le résultat en base64
        BUF_MEM* buf_mem;
        BIO_get_mem_ptr(bio_base64, &buf_mem);

        std::string base64_str(buf_mem->data, buf_mem->length);

        // Libérer les ressources allouées
        BIO_free_all(bio_base64);

        return base64_str;
    }


}

//hash functions 

std::string cryptography::HashFunctions::hash_SHA256(std::string data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);
    std::string result;
    char buf[3];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(buf, "%02x", digest[i]);
        result.append(buf, 2);
    }
    return result;
}

std::string cryptography::HashFunctions::hash_SHA512(std::string data) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);
    std::string result;
    char buf[3];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(buf, "%02x", digest[i]);
        result.append(buf, 2);
    }
    return result;
}


//AES ENCRYPTION AND DECRYPTION functions 

void cryptography::encryption::AES::GENERATE_AES_KEY(std::string& key)
{
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // Générer une clé AES-256
    unsigned char aes_key[AES_KEY_LENGTH/8];
    if (!RAND_bytes(aes_key, sizeof(aes_key))) {
        std::cerr << "Erreur lors de la génération de la clé AES-256" << std::endl;
        return;
    }
    key = std::string(reinterpret_cast<char*>(aes_key), sizeof(aes_key));

    // Nettoyer OpenSSL
    EVP_cleanup();
    RAND_cleanup();
}

void cryptography::encryption::AES::generateEnvironnementVariable(const char* VariableName, std::string Valeur){
    std::string path = std::string(getenv("HOME")) + "/.myapp/";
    struct stat st = {0};
    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), 0700); // Créer le dossier avec les permissions restreintes
    }
    std::ofstream file;
    path += VariableName;
    file.open(path, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        file.write(Valeur.c_str(), Valeur.size());
        file.close();
        chmod(path.c_str(), S_IRUSR | S_IWUSR); // Restreindre les permissions d'accès au fichier
    } 
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier in generate function " << VariableName << std::endl;
        exit(1);
    }   

}

void cryptography::encryption::AES::GENERATE_AES_IV(std::string& iv){

    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // Générer un vecteur d'initialisation AES-256
    unsigned char aes_iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(aes_iv, sizeof(aes_iv))) {
        std::cerr << "Erreur lors de la génération du vecteur d'initialisation AES-256" << std::endl;
        return;
    }
    iv = std::string(reinterpret_cast<char*>(aes_iv), sizeof(aes_iv));

    // Nettoyer OpenSSL
    EVP_cleanup();
    RAND_cleanup();
}

std::string cryptography::encryption::AES::ReadFromFile(const std::string& filename) {
    std::ifstream file;
    std::string path = std::string(getenv("HOME")) + "/.myapp/" + filename;
    file.open(path, std::ios::in | std::ios::binary);
        
    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        std::string value = ss.str();
        file.close();
        return value;
    } else {
        std::cerr << "Erreur lors de l'ouverture du fichier " << filename << std::endl;
        exit(1);
    }
}

std::string cryptography::encryption::AES::PKCS5Padding(const std::string& str)
    {
        size_t padding_size = AES_BLOCK_SIZE - (str.size() % AES_BLOCK_SIZE);
        std::string padding(padding_size, static_cast<char>(padding_size));
        return str + padding;
    }

std::string cryptography::encryption::AES::PKCS5Depadding(const std::string& str)
    {
        size_t padding_size = static_cast<unsigned char>(str.back());
        if (padding_size >= AES_BLOCK_SIZE || str.size() < padding_size) {
            // La chaine n'est pas valide, on peut retourner une erreur ou une chaine vide selon le cas
            return "";
        }
        return str.substr(0, str.size() - padding_size);
    }

void cryptography::encryption::AES::AES_ENCRYPTION(const std::string& data, const std::string& key , const std::string& iv, std::string& encryptedData) {
    OpenSSL_add_all_algorithms();

    // Créer un contexte de chiffrement
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Erreur lors de la création du contexte de chiffrement" << std::endl;
        return;
    }

    // Initialiser le contexte de chiffrement avec la clé et le vecteur d'initialisation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        std::cerr << "Erreur lors de l'initialisation du contexte de chiffrement AES-256 CBC" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Chiffrer les données d'entrée
    std::vector<unsigned char> encrypted(data.size() + AES_BLOCK_SIZE);
    int encrypted_len = 0;
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &encrypted_len, reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) != 1) {
        std::cerr << "Erreur lors du chiffrement des données" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Finaliser le chiffrement
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + encrypted_len, &final_len) != 1) {
        std::cerr << "Erreur lors de la finalisation du chiffrement" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    encrypted_len += final_len;
    encrypted.resize(encrypted_len);

    // Nettoyer le contexte de chiffrement
    EVP_CIPHER_CTX_free(ctx);

    // Convertir les données chiffrées en chaîne binaire
    encryptedData = std::string(encrypted.begin(), encrypted.end());

    // Ajouter le vecteur d'initialisation au début de la chaîne chiffrée
    encryptedData = iv + encryptedData;
}

void cryptography::encryption::AES::AES_DECRYPTION(const std::string& encryptedData, const std::string& key, std::string& decryptedData)
{
    // Récupérer le vecteur d'initialisation de la clé
    std::string iv = encryptedData.substr(0, AES_BLOCK_SIZE);
    std::string encryptedMsg = encryptedData.substr(AES_BLOCK_SIZE);

    // Initialiser les variables OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();

    // Créer un contexte de chiffrement AES CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str());

    // Décrypter les données
    int outputLength = encryptedMsg.length() + AES_BLOCK_SIZE; // La taille de sortie est toujours supérieure ou égale à la taille de l'entrée
    decryptedData.resize(outputLength);
    int actualOutputLength = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decryptedData.data(), &outputLength, (const unsigned char*)encryptedMsg.c_str(), encryptedMsg.length());
    actualOutputLength += outputLength;
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decryptedData.data() + actualOutputLength, &outputLength);
    actualOutputLength += outputLength;
    decryptedData.resize(actualOutputLength);

    // Nettoyer le contexte OpenSSL
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
}


// RSA Functions 

void cryptography::encryption::RSAEncryption::generateEnvironnementVariable(const char* VariableName, std::string Valeur){
    std::string path = std::string(getenv("HOME")) + "/.myapp/";
    struct stat st = {0};
    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), 0700); // Créer le dossier avec les permissions restreintes
    }
    std::ofstream file;
    path += VariableName;
    file.open(path, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        file.write(Valeur.c_str(), Valeur.size());
        file.close();
        chmod(path.c_str(), S_IRUSR | S_IWUSR); // Restreindre les permissions d'accès au fichier
    } 
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier in generate function " << VariableName << std::endl;
        exit(1);
    }   

}

std::string cryptography::encryption::RSAEncryption::ReadFromFile(const std::string& filename, std::string& data) {
    std::ifstream file;
    std::string path = std::string(getenv("HOME")) + "/.myapp/" + filename;
    file.open(path, std::ios::in | std::ios::binary);
        
    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        std::string value = ss.str();
        file.close();
        return value;
    } else {
        std::cerr << "Erreur lors de l'ouverture du fichier " << filename << std::endl;
        exit(1);
    }
}

void cryptography::encryption::RSAEncryption::generateRSAKeyPair(int key_length, std::string& public_key, std::string& private_key) {
    // Initialiser le générateur de nombres aléatoires
    srand(time(NULL));

    // Générer les clés RSA
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length);
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Récupérer le pointeur RSA
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    // Convertir la clé publique en binaire
    BIO* bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_public, rsa);
    BUF_MEM* public_buf = NULL;
    BIO_get_mem_ptr(bio_public, &public_buf);
    public_key = std::string(public_buf->data, public_buf->length);
    BIO_free_all(bio_public);

    // Convertir la clé privée en binaire
    BIO* bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
    BUF_MEM* private_buf = NULL;
    BIO_get_mem_ptr(bio_private, &private_buf);
    private_key = std::string(private_buf->data, private_buf->length);
    BIO_free_all(bio_private);

    // Libérer la mémoire
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
}


std::string cryptography::encryption::RSAEncryption::PKCS1Padding(const std::string& str, int block_size) {
    std::string padded_str(block_size, 0x00);
    int padding_length = block_size - str.length() - 3;
    padded_str[0] = 0x00;
    padded_str[1] = 0x02;
    for (int i = 2; i < padding_length + 2; i++) {
        padded_str[i] = 0xff;
    }
    padded_str[padding_length + 2] = 0x00;
    padded_str += str;
    return padded_str;
}

std::string cryptography::encryption::RSAEncryption::PKCS1Depadding(const std::string& str, RSA* private_key) {

    // Retirer le padding PKCS1
    const int padding_len = RSA_size(private_key) - str.length();
    if (padding_len > 0) {
        throw std::runtime_error("Données de taille incorrecte pour le dépadding RSA PKCS#1 v1.5");
    }
    const unsigned char* str_ptr = reinterpret_cast<const unsigned char*>(str.data());
    std::string depadded_str(RSA_size(private_key) - 11, '\0');
    const int depadded_len = RSA_private_decrypt(str.length(), str_ptr, reinterpret_cast<unsigned char*>(depadded_str.data()), private_key, RSA_PKCS1_PADDING);
    if (depadded_len == -1) {
        throw std::runtime_error("Erreur lors du déchiffrement RSA avec padding PKCS#1 v1.5");
    }
    depadded_str.resize(depadded_len);
    return depadded_str;
}

std::string cryptography::encryption::RSAEncryption::encrypt(const std::string& data, RSA* public_key) {
    int rsa_key_size = RSA_size(public_key);
    std::unique_ptr<unsigned char[]> encrypted_data(new unsigned char[rsa_key_size]);
    int encrypted_data_size = RSA_public_encrypt(static_cast<int>(data.length()), reinterpret_cast<const unsigned char*>(data.data()), encrypted_data.get(), public_key, RSA_PKCS1_PADDING);
    if (encrypted_data_size == -1) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
        throw std::runtime_error("RSA encryption failed");
    }
    std::string binary_encrypted_data(reinterpret_cast<const char*>(encrypted_data.get()), encrypted_data_size);
    return binary_encrypted_data;
}



std::string cryptography::encryption::RSAEncryption::decrypt(const std::string& encryptedData, RSA* private_key) {
    // Decode the Base64 string to binary
    std::string binary_encrypted_data = base64ToBinary(encryptedData);

    // Decrypt the data
    int encrypted_data_size = static_cast<int>(binary_encrypted_data.length());
    int rsa_key_size = RSA_size(private_key);
    std::unique_ptr<unsigned char[]> decrypted_data(new unsigned char[rsa_key_size]);
    int decrypted_data_size = RSA_private_decrypt(rsa_key_size, reinterpret_cast<const unsigned char*>(binary_encrypted_data.data()), decrypted_data.get(), private_key, RSA_PKCS1_PADDING);
    if (decrypted_data_size == -1) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
        throw std::runtime_error("RSA decryption failed");
    }

    // Convert the binary data to a string
    std::string decryptedData = std::string(reinterpret_cast<const char*>(decrypted_data.get()), decrypted_data_size);

    return decryptedData;
}






// elliptic_curve fuctions 

void cryptography::encryption::EllipticCurve::GENERATE_EC_KEYPAIR(EC_KEY*& privateKey, EC_POINT*& publicKey) {
    // Création de la structure de la courbe elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // Génération d'une nouvelle clé privée liée à la courbe
    privateKey = EC_KEY_new();
    EC_KEY_set_group(privateKey, group);
    EC_KEY_generate_key(privateKey);

    // Récupération de la clé publique correspondante
    const EC_POINT* const_pub_key = EC_KEY_get0_public_key(privateKey);
    publicKey = EC_POINT_dup(const_pub_key, group);
    
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, publicKey, x, y, NULL);
    BN_free(y);

    // Conversion du point de la clé publique en une représentation binaire
    size_t buf_len = EC_POINT_point2oct(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::string pubKeyBinary(buf_len, 0);
    unsigned char* pubKeyBinaryPtr = reinterpret_cast<unsigned char*>(&pubKeyBinary[0]);
    EC_POINT_point2oct(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, pubKeyBinaryPtr, buf_len, NULL);

    // Nettoyage des variables temporaires
    BN_free(x);
    EC_GROUP_free(group);
}

void cryptography::encryption::EllipticCurve::generateEnvironnementVariable(const char* VariableName, std::string Valeur){
    std::string path = std::string(getenv("HOME")) + "/.myapp/";
    struct stat st = {0};
    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), 0700); // Créer le dossier avec les permissions restreintes
    }
    std::ofstream file;
    path += VariableName;
    file.open(path, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        file.write(Valeur.c_str(), Valeur.size());
        file.close();
        chmod(path.c_str(), S_IRUSR | S_IWUSR); // Restreindre les permissions d'accès au fichier
    } 
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier in generate function " << VariableName << std::endl;
        exit(1);
    }   

}

std::string cryptography::encryption::EllipticCurve::ReadFromFile(const std::string& filename) {
    std::ifstream file;
    std::string path = std::string(getenv("HOME")) + "/.myapp/" + filename;
    file.open(path, std::ios::in | std::ios::binary);
        
    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        std::string value = ss.str();
        file.close();
        return value;
    } else {
        std::cerr << "Erreur lors de l'ouverture du fichier " << filename << std::endl;
        exit(1);
    }
}

std::string cryptography::encryption::EllipticCurve::encrypt(const std::string& plaintext, const EC_POINT* publicKey){
    //Crée le groupe de la coube elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // Générer une paire de clés éphémères
    EC_KEY* ephemeralKey = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(ephemeralKey);
    const EC_POINT* ephemeralPubKey = EC_KEY_get0_public_key(ephemeralKey);

    // Calculer le secret partagé en utilisant ECDH
    unsigned char secret[48];
    ECDH_compute_key(secret, sizeof(secret), publicKey, ephemeralKey, NULL);

    // Derive the symmetric key and IV from the shared secret using HKDF
    unsigned char derivedKey[48];
    size_t keyLen = sizeof(derivedKey);
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>("ECIES"), 5);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, sizeof(secret));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>("KeyIV"), 5);
    EVP_PKEY_derive(pctx, derivedKey, &keyLen);
    EVP_PKEY_CTX_free(pctx);

    // Chiffrer le texte en clair avec AES-256-GCM
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cipherCtx, EVP_aes_256_gcm(), NULL, derivedKey, derivedKey + 32);
    unsigned char ciphertext[plaintext.size()];
    int outlen;
    EVP_EncryptUpdate(cipherCtx, ciphertext, &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());

    // Obtenir le tag d'authentification
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(cipherCtx);

    // Convertir la clé publique éphémère en une représentation binaire
    size_t ephemeralKeySize = EC_POINT_point2oct(group, ephemeralPubKey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::vector<unsigned char> ephemeralKeyBytes(ephemeralKeySize);
    EC_POINT_point2oct(group, ephemeralPubKey, POINT_CONVERSION_UNCOMPRESSED, ephemeralKeyBytes.data(), ephemeralKeySize, NULL);

    std::string encryptedMessage;
    encryptedMessage.reserve(ephemeralKeySize + plaintext.size() + 16);
    encryptedMessage.append(reinterpret_cast<char*>(ephemeralKeyBytes.data()), ephemeralKeySize);
    encryptedMessage.append(reinterpret_cast<char*>(ciphertext), plaintext.size());
    encryptedMessage.append(reinterpret_cast<char*>(tag), 16);

    // Nettoyer les ressources
    EC_KEY_free(ephemeralKey);
    EC_GROUP_free(group);
    return encryptedMessage;
}

std::string cryptography::encryption::EllipticCurve::decrypt(const std::string& encryptedMessage, EC_KEY* privateKey) {
    
    //Crée le groupe de la coube elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // Extraire la clé publique éphémère, le texte chiffré et le tag d'authentification
    size_t ephemeralKeySize = EC_POINT_point2oct(group, EC_KEY_get0_public_key(privateKey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::vector<unsigned char> ephemeralKeyBytes(ephemeralKeySize);
    std::copy(encryptedMessage.begin(), encryptedMessage.begin() + ephemeralKeySize, ephemeralKeyBytes.begin());
    std::string ciphertext(encryptedMessage.begin() + ephemeralKeySize, encryptedMessage.end() - 16);
    std::string tag(encryptedMessage.end() - 16, encryptedMessage.end());

    // Recréer la clé publique éphémère
    EC_POINT* ephemeralPubKey = EC_POINT_new(group);
    EC_POINT_oct2point(group, ephemeralPubKey, ephemeralKeyBytes.data(), ephemeralKeySize, NULL);

    // Calculer le secret partagé
    unsigned char secret[48];
    ECDH_compute_key(secret, sizeof(secret), ephemeralPubKey, privateKey, NULL);

    // Derive the symmetric key and IV from the shared secret using HKDF
    unsigned char derivedKey[48];
    size_t keyLen = sizeof(derivedKey);
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>("ECIES"), 5);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, sizeof(secret));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>("KeyIV"), 5);
    EVP_PKEY_derive(pctx, derivedKey, &keyLen);
    EVP_PKEY_CTX_free(pctx);

    // Décrypter le texte chiffré
    std::string decryptedText;
    decryptedText.resize(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, derivedKey, derivedKey + 32);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.data()));
    int len;
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decryptedText[0]), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());
    int finalLen;
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decryptedText[0]) + len, &finalLen);
    decryptedText.resize(len + finalLen);

    // Nettoyer les ressources
    EC_POINT_free(ephemeralPubKey);
    EVP_CIPHER_CTX_free(ctx);
    EC_GROUP_free(group);

    return decryptedText;
}




