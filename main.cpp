#include <iostream>
#include <gtk-3.0/gtk/gtkx.h>
#include "cryptography.hpp"
#include "environnement.hpp"
#include <sqlite3.h>
#include <cstdlib>

using namespace std;

bool login(std::string username, std::string password){
    return true;
}
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

bool isRegistered() {
    std::ifstream file(std::string(getenv("HOME")) + "/.myapp/aes_key.bin");
    return file.good() ? true : false;
}

int main() {
    bool registered = isRegistered();
    if (registered) {
        std::cout << "User is registered" << std::endl;
    } else {
        GENERATE_AES_KEY("aes_kek.bin");
        GENERATE_AES_KEY("aes_key.bin");
        cout << "generation done "<< endl;
        LoginEnvironnement::Interface().createUser();
    }
    return 0;
}



