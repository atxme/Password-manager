#include <iostream>
#include <gtk-3.0/gtk/gtk.h>
#include "cryptography.hpp"



int main(){
    
    GtkWidget *main_window;
    GtkWidget *button;

    gtk_init(0,NULL);

    main_window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window),"PasswordManager");
    gtk_window_set_default_size(GTK_WINDOW(main_window),640,480);


    gtk_widget_show_all(main_window);
    gtk_main();
    return 0;
}

