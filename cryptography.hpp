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

#ifndef __include_sha_h__
#define __include_sha_h__
#include <openssl/sha.h>
#endif

#ifndef CRYPTOGRAPHY_HPP
#define CRYPTOGRAPHY_HPP   
#endif 

std::string hash(std::string password);

std::string returnKey();