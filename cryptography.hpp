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
#include <string>
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

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __include_sha_h__
#define __include_sha_h__
#include <openssl/sha.h>
#endif

#ifndef CRYPTOGRAPHY_HPP
#define CRYPTOGRAPHY_HPP   


using namespace std;

std::string hashFunction (std::string password);
std::string binaryToHex(const std::string &binary);
void generateEnvironnementVariable(const char* VariableName, std::string Valeur);
std::string ReadFromFile(std::string filename);
void GENERATE_AES_KEY(std::string nameKeyFile, bool generateKEK );
std::string decrypt(const std::string &data, const std::string &key);
std::string decryptKey();
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);
std::vector<unsigned char> pkcs7_pad(const std::vector<unsigned char> &data);
std::vector<unsigned char> pkcs7_unpad(const std::vector<unsigned char> &data);
std::vector<unsigned char> encrypt(const std::vector<unsigned char> &data, const std::string &target);
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &encrypted_data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);
std::vector<unsigned char> decrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key);


#endif // CRYPTOGRAPHY_HPP