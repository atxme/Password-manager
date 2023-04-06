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

#ifndef __define_aes_size__ 
#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 256
#define AES_KEY_LENGTH 256
#endif 

#include <iomanip>
#include <string>
#include "cryptography.hpp"


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


void generateEnvironnementVariable(const char* VariableName ,std::string Valeur){
    
    setenv(VariableName, Valeur.c_str(), 1);
    std::cout <<"done" << std::endl;
}

void GENERATE_AES_KEY(){
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", 32);

    // Génère une clé AES-256
    unsigned char key[AES_KEY_LENGTH/8];
    if (!RAND_bytes(key, sizeof(key))) {
        std::cerr << "Erreur lors de la génération de la clé AES-256\n";
    }
    
    std::cout << "Clé AES-256 généré avec succès" << std::endl;

    // Nettoie OpenSSL
    EVP_cleanup();
    RAND_cleanup();

    const char* environnement_variable = std::getenv("AES_KEY");
    if (environnement_variable == NULL){
        std::string key_string(reinterpret_cast<char*>(key), sizeof(key));
        setenv("AES_KEY", key_string.c_str(), 1);
    }
    else{  //delete important informations from RAM
        // Note: It's not recommended to use 'delete[]' for memory not allocated by 'new[]'
        // You can use 'memset()' to zero the memory before returning it to the system
        memset(key, 0, sizeof(key));
    }
}

std::string encrypt (unsigned char * key , std::string data){

}