#pragma once

#ifndef DATABASEINTERACTION_HPP
#define DATABASEINTERACTION_HPP

#ifndef SQLITE3_H
#include <sqlite3.h>
#endif

#ifndef IOSTREAM
#include <iostream>
#endif

#ifndef FSTREAM
#include <fstream>
#endif

#ifndef STRING
#include <string>
#endif

#ifndef STDLIB
#include <cstdlib>
#endif

#ifndef CRYPTOGRAPHY_HPP
#include "cryptography_V2.hpp"
#endif

#ifndef DATA
#define DATA
#include "data.hpp"
#endif


#ifndef DATABASE_PATH
#define DATABASE_PATH (std::string(getenv("HOME")) + "/.myapp/" + "database.db").c_str()
#endif

namespace SqlInteractions {

    int passwordCreation(std::string& password);
    int encryptDatabase();
    int decryptDatabase(std::string& password,std::string& salt);

}

#endif

