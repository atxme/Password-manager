#include "databaseInteraction.hpp"

#ifndef CRYPTOGRAPHY_V2_HPP
#include "cryptography_V2.hpp"
#endif

#ifndef SQLITE3_H
#include <sqlite3.h>
#endif

#ifndef FSTREAM
#include <fstream>
#endif

#ifndef TEMP
#define TEMP 
#include "data.hpp"
#endif

#ifndef DATA
#define DATA
#include "data.hpp"
#endif

int SqlInteractions::decryptDatabase(std::string& password,std::string& salt){
    sqlite3* db;
    int rc;

    
    rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc) {
        std::cerr << "Erreur lors de l'ouverture de la base de données : " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::string derivate_key,aes_key,data_decrypted,data_encrypted;
    data_encrypted=cryptography::encryption::AES::ReadFromFile("database.db");
    std::string encrypted_aes_key = cryptography::encryption::AES::ReadFromFile("aes_key.bin");
    cryptography::DerivationKey::pbkf2Derivation(password,salt,100000,32,derivate_key);
    cryptography::encryption::AES::AES_DECRYPTION(encrypted_aes_key,derivate_key,aes_key);
    cryptography::encryption::AES::AES_DECRYPTION(data_encrypted,aes_key,data_decrypted);

    std::ofstream file(DATABASE_PATH);

    if (file.is_open()){
        file.write(data_decrypted.c_str(),data_decrypted.size());
        file.close();
    }
    else{
        std::cerr<<"Erreur lors de l'ouverture du fichier"<<std::endl;
    }

}

int SqlInteractions::encryptDatabase(){
    sqlite3* db;
    int rc;

    
    rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc) {
        std::cerr << "Erreur lors de l'ouverture de la base de données : " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::string derivate_key,derivate_key_encrypted,aes_key,aes_key_encrypted,data_decrypted,data_encrypted;

    derivate_key_encrypted=cryptography::encryption::AES::ReadFromFile("dev_key.bin");
    aes_key_encrypted=cryptography::encryption::AES::ReadFromFile("aes_key.bin");
    cryptography::encryption::AES::AES_DECRYPTION(derivate_key_encrypted,tempkey,derivate_key);
    cryptography::encryption::AES::AES_DECRYPTION(aes_key_encrypted,derivate_key,aes_key);
    data_decrypted=cryptography::encryption::AES::ReadFromFile("database.db");
    cryptography::encryption::AES::AES_ENCRYPTION(data_decrypted,aes_key,tempiv,data_encrypted);

    std::ofstream file(DATABASE_PATH);

    if (file.is_open()){
        file.write(data_encrypted.c_str(),data_encrypted.size());
        file.close();
    }
    else{
        std::cerr<<"Erreur lors de l'ouverture du fichier"<<std::endl;
    }
}

int SqlInteractions::passwordCreation(std::string& password) {
    sqlite3* db;
    int rc;

    
    rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc) {
        std::cerr << "Erreur lors de l'ouverture de la base de données : " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }


    std::string request;
}
