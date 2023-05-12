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

#ifndef __include_bitset__
#define __include_bitset__
#include <bitset>
#endif

#ifndef __include_objmac__
#define __include_objmac__
#include <openssl/obj_mac.h>
#endif

#ifndef __include_bn_h__
#define __include_bn_h__
#include <openssl/bn.h>
#endif

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>

namespace cryptography {

    template <typename T>
    std::string to_binary(const T& data);
    std::string base64ToBinary(const std::string &base64_str);
    std::string binaryToBase64(const std::string& binary_str);

    class HashFunctions {
        public:
            static std::string hash_SHA256(std::string data);
            static std::string hash_SHA512(std::string data);
    };

    class DerivationKey{
        public :
            static void generateSalt(std::string &salt);
            static void pbkf2Derivation(const std::string &password, const std::string &salt, int iteration, int key_length, std::string &key);
    };

    namespace encryption {

        class AES {
            private:
                int key_size;

            public:
                static void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                static void GENERATE_AES_KEY(std::string& key);
                static void GENERATE_AES_IV(std::string& iv);
                static std::string ReadFromFile(const std::string& filename);
                static std::string PKCS5Padding(const std::string& str);
                static std::string PKCS5Depadding(const std::string& str);
                static void AES_ENCRYPTION(const std::string& data, const std::string& key , const std::string& iv, std::string& encryptedData);
                static void AES_DECRYPTION(const std::string& encryptedData, const std::string& key, std::string& decryptedData);
        };

        class RSAEncryption {
            public:
                static void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                static std::string ReadFromFile(const std::string& filename, std::string& data);
                static void generateRSAKeyPair(int key_length, std::string& public_key, std::string& private_key);
                static std::string PKCS1Padding(const std::string& str, int block_size);
                static std::string PKCS1Depadding(const std::string& str, RSA* private_key);
                static std::string encrypt(const std::string& data, RSA* public_key);
                static std::string decrypt(const std::string& encryptedData, RSA* private_key);
        };

        class EllipticCurve {
            public:
                static void GENERATE_EC_KEYPAIR(EC_KEY*& privateKey, EC_POINT*& publicKey);
                static void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
                static std::string ReadFromFile(const std::string& filename);
                static std::string encrypt(const std::string& plaintext, const EC_POINT* publicKey);
                static std::string decrypt(const std::string& encryptedMessage, EC_KEY* privateKey);
        };

    }

}


