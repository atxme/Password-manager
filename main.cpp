#include <iostream>
#include <gtk-3.0/gtk/gtkx.h>
#include "cryptography.hpp"
#include "environnement.hpp"
#include <sqlite3.h>
#include <cstdlib>

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
    bool registered = isRegistered();
    while (LoginEnvironnement::connected == false){

        if (registered) {
            LoginEnvironnement::InterfaceConnect().connectUser();

        } else {
            GENERATE_AES_KEY("aes_kek.bin",true);
            GENERATE_AES_KEY("aes_key.bin",false);
            LoginEnvironnement::Interface().createUser();
        }
        return 0; 
    }
}



