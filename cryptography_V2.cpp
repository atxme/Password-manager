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
#include <pem.h>
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

    std::string binaryToBase64(const std::string& binary_str) {
    // Créer un flux de lecture à partir de la chaîne binaire
    BIO* bio_binary = BIO_new_mem_buf(binary_str.c_str(), -1);

    // Créer un flux d'écriture pour la chaîne Base64
    BIO* bio_base64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

    // Créer un flux de transformation pour le codage Base64
    BIO* bio_encode = BIO_new(BIO_f_bio());
    BIO_push(bio_encode, bio_base64);

    // Écrire la chaîne binaire encodée en Base64 dans le flux de transformation
    char buf[4096];
    int len;
    while ((len = BIO_read(bio_binary, buf, sizeof(buf))) > 0) {
        BIO_write(bio_encode, buf, len);
    }

    // Finaliser la transformation
    BIO_flush(bio_encode);

    // Lire la chaîne Base64 résultante
    BUF_MEM* buf_mem;
    BIO_get_mem_ptr(bio_base64, &buf_mem);
    std::string base64_str(buf_mem->data, buf_mem->length);

    // Nettoyer les flux
    BIO_free_all(bio_binary);
    BIO_free_all(bio_encode);

    return base64_str;
}

    class hashfunctions {
        private :
            std::string hash;

        public :

            std::string hash_SHA256 (std::string data);
            std::string hash_SHA512 (std::string data);
            
    }

    class encryption {

        class AES{
            private :
                int key_size;

            public :
                void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                void GENERATE_AES_KEY(std::string& key);  
                void GENERATE_AES_IV(std::string& iv);
                std::string ReadFromFile(const std::string& filename);
                std::string PKCS5Padding(const std::string& str);
                std::string PKCS5Depadding(const std::string& str);
                cryptography::encryption::AES_ENCRYPTION (const std::string& data, const std::string& key , const std::string& iv, std::string& encryptedData);
                void cryptography::encryption::AES_DECRYPTION(const std::string& encryptedData, const std::string& key, std::string& decryptedData);
                
        }
    

        class RSA {

            private :

                int key_size;

            public :
                void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                void ReadFromFile(const std::string& filename, std::string& data);
                void generateRSAKeyPair(std::string& key);
                std::string PKCS1Padding(const std::string& str, int block_size);
                std::string PKCS1Depadding(const std::string& str);
                std::string encrypt(const std::string& plaintext, const std::string& publicKeyFilename);
                std::string decrypt(const std::string& encryptedData, const std::string& privateKeyPath, std::string& decryptedData)
        }


        class elliptic_curve {

            private :
                int key_size;

            public :
                void GENERATE_EC_KEYPAIR(EC_KEY*& privateKey, EC_POINT*& publicKey);
                void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                std::string ReadFromFile(const std::string& filename);
                std::string encrypt(const std::string& plaintext, const EC_POINT* publicKey);
                std::string decrypt(const std::string& encryptedMessage, EC_KEY* privateKey);
        }
    }
}

//hash functions 

std::string cryptography::hashfunctions::hash_SHA256(std::string data) {
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

std::string cryptography::hashfunctions::hash_SHA512(std::string data) {
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
    ERR_load_crypto_strings();

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

void cryptography::encryption::RSA::generateEnvironnementVariable(const char* VariableName, std::string Valeur){
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

std::string cryptography::encryption::RSA::ReadFromFile(const std::string& filename) {
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

void cryptography::encryption::RSA::generateRSAKeyPair(int key_length, std::string& public_key, std::string& private_key) {
    // Initialiser le générateur de nombres aléatoires
    srand(time(NULL));

    // Générer les clés RSA
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length);
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Convertir la clé publique en binaire
    BIO* bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_public, pkey->pkey.rsa);
    BUF_MEM* public_buf = NULL;
    BIO_get_mem_ptr(bio_public, &public_buf);
    public_key = std::string(public_buf->data, public_buf->length);
    BIO_free_all(bio_public);

    // Convertir la clé privée en binaire
    BIO* bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL);
    BUF_MEM* private_buf = NULL;
    BIO_get_mem_ptr(bio_private, &private_buf);
    private_key = std::string(private_buf->data, private_buf->length);
    BIO_free_all(bio_private);

    // Libérer la mémoire
    EVP_PKEY_free(pkey);
    ERR_free_strings();
}

std::string cryptography::encryption::RSA::PKCS1Padding(const std::string& str, int block_size) {
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

std::string cryptography::encryption::RSA::PKCS1Depadding(const std::string& str) {

    // Retirer le padding PKCS1
    const int padding_len = RSA_size(cryptography::keys::private_key.get()) - str.length();
    if (padding_len > 0) {
        throw std::runtime_error("Données de taille incorrecte pour le dépadding RSA PKCS#1 v1.5");
    }
    const unsigned char* str_ptr = reinterpret_cast<const unsigned char*>(str.data());
    std::string depadded_str(RSA_size(cryptography::keys::private_key.get()) - 11, '\0');
    const int depadded_len = RSA_private_decrypt(str.length(), str_ptr, reinterpret_cast<unsigned char*>(depadded_str.data()), cryptography::keys::private_key.get(), RSA_PKCS1_PADDING);
    if (depadded_len == -1) {
        throw std::runtime_error("Erreur lors du déchiffrement RSA avec padding PKCS#1 v1.5");
    }
    depadded_str.resize(depadded_len);
    return depadded_str;
}

std::string cryptography::encryption::RSA::encrypt(const std::string& data, const std::string& public_key_file, std::string& encrypted_data) {
    // Lire la clé publique RSA à partir du fichier
    RSA* public_key = nullptr;
    FILE* public_key_fp = fopen(public_key_file.c_str(), "rb");
    if (public_key_fp == nullptr) {
        throw std::runtime_error("Could not open public key file: " + public_key_file);
    }
    public_key = PEM_read_RSA_PUBKEY(public_key_fp, &public_key, nullptr, nullptr);
    fclose(public_key_fp);
    if (public_key == nullptr) {
        throw std::runtime_error("Could not read public key from file: " + public_key_file);
    }

    // Chiffrer les données avec la clé publique RSA
    const int rsa_size = RSA_size(public_key);
    std::vector<uint8_t> rsa_input(rsa_size - 11);
    std::vector<uint8_t> rsa_output(rsa_size);
    std::string padded_data = PKCS1Padding(data, rsa_size - 11);
    for (size_t i = 0; i < padded_data.size(); i += rsa_size - 11) {
        const int len = std::min<int>(rsa_size - 11, padded_data.size() - i);
        memcpy(rsa_input.data(), padded_data.data() + i, len);
        const int rsa_result = RSA_public_encrypt(len, rsa_input.data(), rsa_output.data(), public_key, RSA_PKCS1_PADDING);
        if (rsa_result == -1) {
            RSA_free(public_key);
            throw std::runtime_error("RSA encryption failed");
        }
        encrypted_data += std::string(rsa_output.begin(), rsa_output.begin() + rsa_result);
    }

    // Libérer la mémoire et nettoyer
    RSA_free(public_key);
}

std::string cryptography::encryption::RSA::decrypt(const std::string& encryptedData, const std::string& privateKeyPath, std::string& decryptedData) {
    // Chargement de la clé privée RSA
    RSA* private_key = NULL;
    FILE* private_key_file = fopen(privateKeyPath.c_str(), "rb");
    if (!private_key_file) {
        throw std::runtime_error("Failed to open private key file for reading");
    }
    private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!private_key) {
        throw std::runtime_error("Failed to load private key");
    }

    // Décodage de la chaîne Base64 en binaire
    std::string binary_encrypted_data = base64ToBinary(encryptedData);

    // Décryptage des données
    int encrypted_data_size = static_cast<int>(binary_encrypted_data.length());
    int rsa_key_size = RSA_size(private_key);
    std::unique_ptr<unsigned char[]> decrypted_data(new unsigned char[rsa_key_size]);
    int decrypted_data_size = RSA_private_decrypt(encrypted_data_size, reinterpret_cast<const unsigned char*>(binary_encrypted_data.c_str()), decrypted_data.get(), private_key, RSA_PKCS1_PADDING);
    if (decrypted_data_size == -1) {
        RSA_free(private_key);
        throw std::runtime_error("RSA decryption failed");
    }

    // Conversion du binaire en chaîne de caractères
    decryptedData = std::string(reinterpret_cast<const char*>(decrypted_data.get()), decrypted_data_size);

    // Nettoyage de la mémoire
    RSA_free(private_key);
}


// elliptic_curve fuctions 

void cryptography::encryption::elliptic_curve::GENERATE_EC_KEYPAIR(EC_KEY*& privateKey, EC_POINT*& publicKey){
    // Création de la structure de la courbe elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // Génération d'une nouvelle clé privée liée à la courbe
    privateKey = EC_KEY_new();
    EC_KEY_set_group(privateKey, group);
    EC_KEY_generate_key(privateKey);

    // Récupération de la clé publique correspondante
    publicKey = EC_KEY_get0_public_key(privateKey);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, publicKey, x, y, NULL);
    BN_free(y);

    // Conversion du point de la clé publique en une représentation binaire
    int buf_len = EC_POINT_point2buf(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    std::string pubKeyBinary(buf_len, 0);
    EC_POINT_point2buf(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)&pubKeyBinary[0], buf_len, NULL);

    // Nettoyage des variables temporaires
    BN_free(x);
    EC_GROUP_free(group);
}

void cryptography::encryption::elliptic_curve::generateEnvironnementVariable(const char* VariableName, std::string Valeur){
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

std::string cryptography::encryption::elliptic_curve::ReadFromFile(const std::string& filename) {
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

std::string cryptography::encryption::elliptic_curve::encrypt(const std::string& plaintext, const EC_POINT* publicKey){
    //Crée le groupe de la coube elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    
    
    // Générer une paire de clés éphémères
    EC_KEY* ephemeralKey = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(ephemeralKey);
    const EC_POINT* ephemeralPubKey = EC_KEY_get0_public_key(ephemeralKey);

    // Calculer le secret partagé en utilisant ECDH
    unsigned char secret[48];
    ECDH_compute_key(secret, sizeof(secret), publicKey, ephemeralKey, NULL);

    // Dérivation de la clé symétrique et de l'IV à partir du secret partagé en utilisant HKDF
    unsigned char derivedKey[48];
    size_t keyLen = sizeof(derivedKey);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, "ECIES", 5); // Utiliser "ECIES" comme sel
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, sizeof(secret));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, "KeyIV", 5); // Utiliser "KeyIV" comme info HKDF
    EVP_PKEY_derive(pctx, derivedKey, &keyLen);
    EVP_PKEY_CTX_free(pctx);

    // Chiffrer le texte en clair avec AES-256-GCM
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(cipherCtx, EVP_aes_256_gcm(), derivedKey, derivedKey + 32);
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


std::string cryptography::encryption::elliptic_curve::decrypt(const std::string& encryptedMessage, EC_KEY* privateKey) {
    
    //Crée le groupe de la coube elliptique à utiliser
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // Extraire la clé publique éphémère, le texte chiffré et le tag d'authentification
    size_t ephemeralKeySize = EC_POINT_point2oct(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
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

    // Dérivez la clé symétrique et l'IV à partir du secret partagé
    unsigned char derivedKey[48];
    size_t keyLen = 32;
    size_t ivLen = 16;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, "ECIES", 5); // Utilisez "ECIES" comme sel
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, sizeof(secret));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, "KeyIV", 5); // Utilisez "KeyIV" comme information HKDF
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




