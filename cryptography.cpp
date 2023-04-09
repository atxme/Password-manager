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
#define AES_BLOCK_SIZE 256
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


void generateEnvironnementVariable(const char* VariableName, std::string Valeur){
    cout << "Generating environnement variable" << VariableName<<endl;
    std::string path = std::string(getenv("HOME")) + "/.myapp/";
    struct stat st = {0};
    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), 0700); // Créer le dossier avec les permissions restreintes
    }
    else{
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
    
}

std::string ReadFromFile(std::string filename){
    std::ifstream file;
    std::string path = std::string(getenv("HOME")) + "/.myapp/" + filename;
    if (filename == "hash_login.bin"){
        file.open(path, std::ios::in);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }
        std::string hash;
        std::getline(file, hash);
        file.close();
        return hash;
    }
    else {
        file.open(path, std::ios::in | std::ios::binary);
        if (file.is_open()) {
            std::string value;
            file.seekg(0, std::ios::end);
            value.reserve(file.tellg());
            file.seekg(0, std::ios::beg);
            value.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            return value;
        } else {
            std::cerr << "Erreur lors de l'ouverture du fichier " << filename << std::endl;
            exit(1);
        }
    }
}


void GENERATE_AES_KEY(std::string nameKeyFile){
    
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);
    // Génère une clé AES-256
    unsigned char key[AES_KEY_LENGTH/8];
    if (!RAND_bytes(key, sizeof(key))) {
        std::cerr << "Erreur lors de la génération de la clé AES-256\n";
    }
    std::string key_string(reinterpret_cast<char*>(key), sizeof(key));

    // Nettoie OpenSSL
    EVP_cleanup();
    RAND_cleanup();

    if (nameKeyFile=="aes_key.bin") {
        // Vérifie si le fichier existe déjà avant de le générer
        std::string aes_key_path = std::string(getenv("HOME")) + "/.myapp/aes_key.bin";
        bool aes_key_exists = std::ifstream(aes_key_path).good();
        if (!aes_key_exists) {
            // Génère la clé kek s'il n'existe pas
            std::string kek_path = std::string(getenv("HOME")) + "/.myapp/aes_kek.bin";
            bool kek_exists = std::ifstream(kek_path).good();
            if (!kek_exists) {
                generateEnvironnementVariable("aes_kek.bin", key_string);
            }
            std::string key_string_encrypt = encrypt(key_string, "Create_User");
            generateEnvironnementVariable(nameKeyFile.c_str(), key_string_encrypt);
        }
    }
    else {
        // Génère la clé kek s'il n'existe pas
        std::string kek_path = std::string(getenv("HOME")) + "/.myapp/aes_kek.bin";
        bool kek_exists = std::ifstream(kek_path).good();
        if (!kek_exists) {
            generateEnvironnementVariable("aes_kek.bin", key_string);
        }
        generateEnvironnementVariable(nameKeyFile.c_str(), key_string);
    }
    memset(key, 0, sizeof(key));    
}


std::string decrypt(std::string data, std::string key){
    std::string decryptData;
    unsigned char iv[AES_BLOCK_SIZE/8];
    unsigned char key_decrypt[AES_KEY_LENGTH/8];
    memcpy(key_decrypt, key.c_str(), sizeof(key_decrypt));
    AES_KEY aes_key;
    AES_set_decrypt_key(key_decrypt, sizeof(key_decrypt)*8, &aes_key);
    unsigned char decrypted_text[data.size()];
    AES_cbc_encrypt((unsigned char*)data.c_str(), decrypted_text, data.size(), &aes_key, iv, AES_DECRYPT);
    decryptData = (char*)decrypted_text;
    return decryptData;
}

std::string encrypt(std::string data, std::string target){
    std::string key;
    if (target == "Create_User"){
        std::string encryptData;
        std::string key;
        std::string kek_path = std::string(getenv("HOME")) + "/.myapp/aes_kek.bin";
        bool kek_exists = std::ifstream(kek_path).good();
        if (kek_exists) {
            key = ReadFromFile("aes_kek.bin");
        } else {
            GENERATE_AES_KEY("aes_kek.bin");
            key = ReadFromFile("aes_kek.bin");
        }
        unsigned char iv[AES_BLOCK_SIZE/8];
        unsigned char key_encrypt[AES_KEY_LENGTH/8];
        memcpy(key_encrypt, key.c_str(), sizeof(key_encrypt));
        AES_KEY aes_key;
        AES_set_encrypt_key(key_encrypt, sizeof(key_encrypt)*8, &aes_key);
        unsigned char encrypted_text[data.size()];
        AES_cbc_encrypt((unsigned char*)data.c_str(), encrypted_text, data.size(), &aes_key, iv, AES_ENCRYPT);
        encryptData = (char*)encrypted_text;
        return encryptData;
    }

    else{
        std::string encryptData;
        std::string aes_key_file = std::string(getenv("HOME")) + "/.myapp/aes_key.bin";
        bool aes_key_exists = std::ifstream(aes_key_file).good();
        if (aes_key_exists) {
            key = ReadFromFile("aes_key.bin");
            std::string key_decrypt=ReadFromFile("aes_kek.bin");
            std::string decrypted_key=decrypt(key,key_decrypt);
            unsigned char iv[AES_BLOCK_SIZE/8];
            unsigned char key_encrypt[AES_KEY_LENGTH/8];
            memcpy(key_encrypt, decrypted_key.c_str(), sizeof(key_encrypt));
            AES_KEY aes_key;
            AES_set_encrypt_key(key_encrypt, sizeof(key_encrypt)*8, &aes_key);
            unsigned char encrypted_text[data.size()];
            AES_cbc_encrypt((unsigned char*)data.c_str(), encrypted_text, data.size(), &aes_key, iv, AES_ENCRYPT);
            encryptData = (char*)encrypted_text;
            return encryptData;
        } else {
            std::cerr << "Le fichier aes_key.bin n'existe pas." << std::endl;
            exit(1);
        }
    }
}
