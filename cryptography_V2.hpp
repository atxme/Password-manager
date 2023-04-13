#pragma once 


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


namespace cryptography {

    template <typename T>
    std::string to_binary(const T& data);
    std::string binaryToBase64(const std::string& binary_str);

    class hashfunctions {
        private :
            std::string data;

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

        class RSA{
            private :
                int key_size;

            public :
                void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                void ReadFromFile(const std::string& filename, std::string& data);
                void generateRSAKeyPair(RSA*& privateKey, RSA*& publicKey);
                std::string PKCS1Padding(const std::string& str, int block_size);
                std::string PKCS1Depadding(const std::string& str);
                std::string encrypt(const std::string& plaintext, const std::string& publicKeyFilename);
                std::string decrypt(const std::string& encryptedData, const std::string& privateKeyPath, std::string& decryptedData);
        }

        class elliptic_curve{
            private :
                int key_size;

            public :
                void GENERATE_EC_KEYPAIR(EC_KEY*& privateKey, EC_POINT*& publicKey);
                void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                std::string ReadFromFile(const std::string& filename);
                std::string encrypt(const std::string& plaintext, const std::string& publicKeyFilename);
                std::string decrypt(const std::string& encryptedData, const std::string& privateKeyPath, std::string& decryptedData);

        }

    }
}

#endif  