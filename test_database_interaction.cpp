#include "databaseInteraction.hpp"
#include "cryptography_V2.hpp"
#include <thread>
#include <chrono>
#include <iostream>
#include "data.hpp"

using namespace std;
using namespace SqlInteractions;

std::string tempkey,tempiv;
std::string password="Christophe15";
std::string salt= cryptography::encryption::AES::ReadFromFile("salt.bin");
std::string dev_key,aes_iv;
cryptography::encryption::AES::GENERATE_AES_KEY(dev_key);
cryptography::encryption::AES::GENERATE_AES_IV(aes_iv);

int main(){
    SqlInteractions::encryptDatabase();
    std::cout<< "Database encrypted"<<std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(15));
    SqlInteractions::decryptDatabase(password,salt);
    std::cout<<"Database decrypted"<<std::endl;
}

