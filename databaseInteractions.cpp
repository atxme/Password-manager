#include "databaseInteraction.hpp"

SqlInteractions::passwordCreation(std::string& password) {
    sqlite3* db;
    int rc;

    
    rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc) {
        std::cerr << "Erreur lors de l'ouverture de la base de données : " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }


    std::string request
}
