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
    std::ifstream file (std::string(getenv("HOME")) + "/.myapp/aes_key.bin");
    if (file.good()) {
        file.close();
        return true;
    }
    else {
        return false;
    }
}


int main(){
    
    bool registered = isRegistered();
    if(!registered){
        LoginEnvironnement::Interface interface;
        interface.createUser();
    }
    else {

        
    }
    
   return 0;
}

