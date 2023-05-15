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
#include "cryptography.hpp"
#endif

#ifndef DATABASE_PATH
#define DATABASE_PATH (std::string(getenv("HOME")) + "/.myapp/" + filename).c_str()
#endif

namespace SqlInteractions {

    std::string passwordCreation(std::string& password) {
        
    }

}

#endif

