#pragma once 

#ifndef __include_IOStream_h__
#define __include_IOStream_h__
#include <iostream>
#endif

#ifndef __include_vector_h__
#define __include_vector_h__
#include <vector>
#endif

#ifndef __include_string__
#define __include_string__
#include <string.h>
#endif

#ifndef __include_cryptography__
#define __include_cryptography__
#include "cryptography.hpp"
#endif

#ifndef __include_gtk__
#define __include_gtk__
#include <gtk-3.0/gtk/gtkx.h>
#endif

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

using namespace std;

namespace LoginEnvironnement {

    static bool connected = false; //update the parameter when the user is connected
    
    class Interface {

    private:
        std::string password;

    public:
        void createUser();
        static void buttonClicked(GtkWidget *widget, gpointer data, gpointer Window);
        static void togglePassword(GtkWidget *widget, gpointer data);
    };

    class InterfaceConnect{
    private:
        std::string password;

    public :
        void connectUser();
        static void buttonClicked(GtkWidget *widget, gpointer data, gpointer Window);
        static void togglePassword(GtkWidget *widget, gpointer data);
    };


}