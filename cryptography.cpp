/*
||---------------------------------------------------------------------------------------------||
||---------------------------------------------------------------------------------------------||
||                                                                                             ||
|| This software is provided "as is" without warranty of any kind, either express or implied.  || 
||  The author of the software is not responsible for any damage caused by the software.       ||
||                                                                                             ||
||  You are not authorized to use this software without the agreement of the author.           || 
||                                                                                             ||    
||  This software uses the openssl library wich renforced cryptography algorithms.             ||
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

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __define_aes_size__ 
#define AES_KEY_SIZE 256
#define AES_KEY_LENGTH 256
#endif 

#include <iomanip>
#include <string>
#include <cstdlib>
#include <sys/stat.h>
#include <fstream>
#include <filesystem>
#include "cryptography.hpp"



using namespace std;

std::string hashFunction (std::string password){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);
    char mdString[SHA256_DIGEST_LENGTH*2+1];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)hash[i]);
    return mdString;
}

std::string binaryToHex(const std::string &binary) {
    std::string hex;
    for (const auto &byte : binary) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned char>(byte));
        hex.append(buf);
    }
    return hex;
}


void generateEnvironnementVariable(const char* VariableName, std::string Valeur){
    
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

std::string ReadFromFile(std::string filename) {
    std::ifstream file;
    std::string path = std::string(getenv("HOME")) + "/.myapp/" + filename;
    if (filename == "hash_login.bin") {
        file.open(path, std::ios::in);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }
        std::string hash;
        std::getline(file, hash);
        file.close();
        return hash;
    } else {
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
}


static int keyGenerate[2]={0,0};

void GENERATE_AES_KEY(std::string nameKeyFile, bool generateKEK = true) {
    // Vérifier si la clé a déjà été générée
    int keyIndex = -1;
    if (nameKeyFile == "aes_kek.bin") {
        keyIndex = 0;
    } else if (nameKeyFile == "aes_key.bin") {
        keyIndex = 1;
    }

    if (keyIndex >= 0 && keyGenerate[keyIndex] == 1) {
        return;
    }

    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // Générer une clé AES-256
    unsigned char key[AES_KEY_LENGTH/8];
    if (!RAND_bytes(key, sizeof(key))) {
        std::cerr << "Erreur lors de la génération de la clé AES-256" << std::endl;
        return;
    }
    std::string key_string(reinterpret_cast<char*>(key), sizeof(key));

    // Nettoyer OpenSSL
    EVP_cleanup();
    RAND_cleanup();

    // Générer la clé KEK s'il n'existe pas et si l'option est activée
    if (generateKEK) {
        std::string kek_path = std::string(getenv("HOME")) + "/.myapp/aes_kek.bin";
        bool kek_exists = std::ifstream(kek_path).good();
        if (!kek_exists && nameKeyFile == "aes_key.bin") {
            GENERATE_AES_KEY("aes_kek.bin", false);
        }
    }

    // Générer la clé demandée
    std::string key_string_encrypt;
    if (nameKeyFile == "aes_kek.bin") {
        key_string_encrypt = key_string;
    } 
    else {
        std::vector<unsigned char> key_string_encrypt = encrypt(std::vector<unsigned char>(key_string.begin(), key_string.end()), "Create_User");

    }
    generateEnvironnementVariable(nameKeyFile.c_str(), key_string_encrypt);
    // Marquer la clé comme générée
    if (keyIndex >= 0) {
        keyGenerate[keyIndex] = 1;
    }
    memset(key, 0, sizeof(key));
    
}


std::string decrypt(const std::string &data, const std::string &key) {
    std::string decryptedData;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char key_decrypt[AES_KEY_SIZE/8];
    memcpy(key_decrypt, key.c_str(), AES_KEY_SIZE/8);
    AES_KEY aes_key;
    AES_set_decrypt_key(key_decrypt, AES_KEY_SIZE, &aes_key);
    int num = 0;
    while (num < data.size()) {
        unsigned char decrypted_text[AES_BLOCK_SIZE];
        AES_cbc_encrypt((const unsigned char*)(&data[num]), decrypted_text, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
        decryptedData.append((char*)decrypted_text, AES_BLOCK_SIZE);
        num += AES_BLOCK_SIZE;
    }

    // Remove padding (PKCS#7)
    size_t padding_length = static_cast<size_t>(decryptedData.back());
    if (padding_length > 0 && padding_length <= AES_BLOCK_SIZE) {
        decryptedData.erase(decryptedData.end() - padding_length, decryptedData.end());
    }

    return decryptedData;
}


std::string decryptKey(){
    std::string key_kek=ReadFromFile("aes_kek.bin");
    std::string encripted_key_aes=ReadFromFile("aes_key.bin");
    std::string key_aes=decrypt(encripted_key_aes, key_kek);
    memset(&key_kek, 0, sizeof(key_kek)); // Effacer la clé KEK de la mémoire
    memset(&encripted_key_aes, 0, sizeof(encripted_key_aes)); // Effacer la clé AES de la mémoire
    return key_aes;
}

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
    std::vector<unsigned char> encrypted_data(data.size() + AES_BLOCK_SIZE);

    memcpy(&encrypted_data[0], iv.data(), AES_BLOCK_SIZE);

    AES_KEY aes_key;
    AES_set_encrypt_key(key.data(), key.size() * 8, &aes_key);

    AES_cbc_encrypt(data.data(), encrypted_data.data() + AES_BLOCK_SIZE, data.size(), &aes_key, const_cast<unsigned char*>(iv.data()), AES_ENCRYPT);

    return encrypted_data;
}


std::vector<unsigned char> pkcs7_pad(const std::vector<unsigned char> &data) {
    size_t padding_length = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    std::vector<unsigned char> padded_data(data);
    padded_data.insert(padded_data.end(), padding_length, static_cast<unsigned char>(padding_length));
    return padded_data;
}

std::vector<unsigned char> pkcs7_unpad(const std::vector<unsigned char> &data) {
    size_t padding_length = static_cast<size_t>(data.back());
    std::vector<unsigned char> unpadded_data(data.begin(), data.end() - padding_length);
    return unpadded_data;
}

std::vector<unsigned char> encrypt(const std::vector<unsigned char> &data, const std::string &target) {
    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> key;

    if (target == "Create_User") {
        key = std::vector<unsigned char>(ReadFromFile("aes_kek.bin").begin(), ReadFromFile("aes_kek.bin").end());
    } else {
        std::string aes_key_file = std::string(getenv("HOME")) + "/.myapp/aes_key.bin";
        bool aes_key_exists = std::ifstream(aes_key_file).good();
        if (aes_key_exists) {
            key = std::vector<unsigned char>(decrypt(ReadFromFile("aes_key.bin"), ReadFromFile("aes_kek.bin")).begin(), decrypt(ReadFromFile("aes_key.bin"), ReadFromFile("aes_kek.bin")).end());

        } else {
            std::cerr << "Le fichier aes_key.bin n'existe pas." << std::endl;
            exit(1);
        }
    }

    std::vector<unsigned char> padded_data = pkcs7_pad(data);

    // Utiliser un IV fixe
    std::vector<unsigned char> iv(AES_BLOCK_SIZE, 0);

    encrypted_data = aes_encrypt(padded_data, key, iv);

    // Insérer l'IV au début des données chiffrées
    encrypted_data.insert(encrypted_data.begin(), iv.begin(), iv.end());

    return encrypted_data;
}


std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &encrypted_data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv)
{
    if (encrypted_data.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Encrypted data is too short");
    }

    std::vector<unsigned char> iv_vec(AES_BLOCK_SIZE);
    memcpy(iv_vec.data(), encrypted_data.data(), AES_BLOCK_SIZE);

    size_t data_size = encrypted_data.size() - AES_BLOCK_SIZE;
    std::vector<unsigned char> decrypted_data(data_size);

    AES_KEY aes_key;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.data()), key.size() * 8, &aes_key);

    AES_cbc_encrypt(encrypted_data.data() + AES_BLOCK_SIZE, decrypted_data.data(), data_size, &aes_key, iv_vec.data(), AES_DECRYPT);

    // Remove padding (PKCS#7)
    size_t padding_length = static_cast<size_t>(decrypted_data.back());
    if (padding_length > 0 && padding_length <= AES_BLOCK_SIZE) {
        decrypted_data.erase(decrypted_data.end() - padding_length, decrypted_data.end());
    } 
    else {
        throw std::runtime_error("Invalid padding length");
    }

    return decrypted_data;
}


std::vector<unsigned char> decrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> decrypted_data;

    // Extraire l'IV du début des données chiffrées
    std::vector<unsigned char> iv(data.begin(), data.begin() + AES_BLOCK_SIZE);

    // Supprimer l'IV des données chiffrées
    std::vector<unsigned char> encrypted_data(data.begin() + AES_BLOCK_SIZE, data.end());

    decrypted_data = aes_decrypt(encrypted_data, key, iv);

    std::vector<unsigned char> unpadded_data = pkcs7_unpad(decrypted_data);
    return unpadded_data;
}
