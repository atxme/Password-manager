#include <iostream>
#include <gtk-3.0/gtk/gtkx.h>
#include "cryptography.hpp"
#include "environnement.hpp"

bool login(std::string username, std::string password){
    return true;
}

bool isRegistered()
{
    const char* key = getenv("AES_KEY");
    if(key == NULL){
        return false;
    }
    delete key;
    return true;
}
int main(){
    
    bool registered = isRegistered();
    if(!registered){
        LoginEnvironnement::Interface interface;
        interface.createUser();
    }
   return 0;
}

