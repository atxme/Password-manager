#include <iostream>
#include <gtk-3.0/gtk/gtkx.h>
#include "cryptography.hpp"
#include "environnement.hpp"
#include <sqlite3.h>

bool login(std::string username, std::string password){
    return true;
}

bool isRegistered()
{
    char* key = getenv("AES_KEY");
    std::string keyString = std::string(key);
    std::cout <<key <<endl;
    if(!key){
        return false;
    }
    memset(key, 0, strlen(key)); // effacer la valeur de la variable dans la mémoire
    return true;
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

