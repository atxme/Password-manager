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
    std::string filePath = std::string(getenv("HOME")) + "/.myapp/aes_key.bin";
    //std::cout << "Chemin d'accès au fichier : " << filePath << std::endl;

    std::ifstream file(filePath);
    if (file.good()) {
        return true; // Le fichier existe
    } else {
        return false; // Le fichier n'existe pas
    }
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

    while (true) {
        bool registered = isRegistered();

        if (registered) {
            LoginEnvironnement::InterfaceConnect().connectUser();
            break; // L'utilisateur s'est connecté avec succès, sortir de la boucle
        } else {
            LoginEnvironnement::Interface().createUser();
            registered = isRegistered();
            if (registered) {
                LoginEnvironnement::InterfaceConnect().connectUser();
                break; // L'utilisateur s'est enregistré et connecté, sortir de la boucle
            }
        }
    }
    cout << "Welcome" << endl;
    return 0;
}

