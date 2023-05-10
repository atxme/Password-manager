#include <iostream>
#include <gtk-3.0/gtk/gtkx.h>
#include "cryptography_V2.hpp"
#include "environnement.hpp"
#include <sqlite3.h>
#include <cstdlib>
#include<unistd.h>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <stdexcept>


using namespace std;

bool login(std::string username, std::string password){
    return true;
}


bool isRegistered() {
    std::ifstream file(std::string(getenv("HOME")) + "/.myapp/aes_key.bin");
    return file.good() ? true : false;
}

int main() {

    // Check if the program is run as root
    if (getuid() != 0) {
        std::cerr << "Erreur : ce programme doit être exécuté en tant que superutilisateur (root)" << std::endl;
        return 1;
    }

    if (setuid(0) != 0) {
        std::cerr << "Erreur lors de la définition de l'UID effectif en tant que superutilisateur (root)" << std::endl;
        return 1;
    }
    bool registered = isRegistered();
    while (true){

        if (registered) {
            LoginEnvironnement::InterfaceConnect().connectUser();

        } else {
            std::string aes_kek, aes_key,aes_key_encrypted,iv;
            cryptography::encryption::AES::GENERATE_AES_KEY(aes_kek);   
            cryptography::encryption::AES::GENERATE_AES_KEY(aes_key);   
            cryptography::encryption::AES::GENERATE_AES_IV(iv);

            cryptography::encryption::AES::AES_ENCRYPTION(aes_key, aes_kek,iv,aes_key_encrypted);

            cryptography::encryption::AES::generateEnvironnementVariable("aes_kek.bin", aes_kek);
            cryptography::encryption::AES::generateEnvironnementVariable("aes_key.bin", aes_key_encrypted);  

            std::cout << "AES KEK: " << cryptography::binaryToBase64(aes_kek)<< std::endl;
            std::cout << "AES key: " << cryptography::binaryToBase64(aes_key)<< std::endl;
            LoginEnvironnement::Interface().createUser();
        }
        return 0; 
    }
    
}



