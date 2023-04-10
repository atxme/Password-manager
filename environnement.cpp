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

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __include_gtk__
#define __include_gtk__
#include <gtk-3.0/gtk/gtkx.h>
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

// create user interface 

void LoginEnvironnement::Interface::togglePassword(GtkWidget *widget, gpointer data) {
    GtkWidget *entry = GTK_WIDGET(data);
    if (gtk_entry_get_visibility(GTK_ENTRY(entry))) {
        gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
        gtk_button_set_label(GTK_BUTTON(widget), "Show");
    } else {
        gtk_entry_set_visibility(GTK_ENTRY(entry), TRUE);
        gtk_button_set_label(GTK_BUTTON(widget), "Hide");
    }
}

void LoginEnvironnement::Interface::buttonClicked(GtkWidget *widget, gpointer data, gpointer Window) {
    const gchar *entry_text;
    std::string hashpassword;
    entry_text = gtk_entry_get_text(GTK_ENTRY(data));
    std::string password = std::string(entry_text);
    hashpassword = hashFunction(password);
    cout << "le hash normal "<< hashpassword << endl;
    std::string encryptPassword = encrypt(hashpassword, "Create_User");
    cout << "le hash encrypter "<< encryptPassword << endl;
    generateEnvironnementVariable("hash_login.bin", encryptPassword);
    gtk_main_quit(); // quitter le main loop de GTK+
}

void LoginEnvironnement::Interface::createUser() {
    GtkWidget *createUserwindow;
    GtkWidget *button;
    GtkWidget *entry;
    GtkWidget *grid;
    GtkWidget *vbox;
    GtkWidget *toggleButton;
    GtkCssProvider *provider, *provider2;

    gtk_init(0, NULL);

    createUserwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(createUserwindow), 640, 480);
    g_signal_connect(createUserwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(createUserwindow), grid);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    GdkRGBA startColor, endColor;
    gdk_rgba_parse(&startColor, "#A5D6A7");
    gdk_rgba_parse(&endColor, "#1B5E20");

    provider = gtk_css_provider_new();
    gchar *cssData = g_strdup_printf("window { background-image: linear-gradient(to bottom, %s, %s); }",
                                      gdk_rgba_to_string(&startColor), gdk_rgba_to_string(&endColor));
    gtk_css_provider_load_from_data(provider, cssData, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    gtk_grid_attach(GTK_GRID(grid), vbox, 1, 1, 1, 1);

    entry = gtk_entry_new();
    gtk_widget_set_size_request(entry, 200, 30); // Ajuster la taille de la zone de texte
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE); // Masquer le texte entré

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    toggleButton = gtk_button_new_with_label("Show");
    gtk_box_pack_end(GTK_BOX(hbox), toggleButton, FALSE, FALSE, 0);

    button = gtk_button_new_with_label("Create your password");
    gtk_widget_set_size_request(button, 100, 30); // Ajuster la taille du bouton

    provider2 = gtk_css_provider_new();
    cssData = g_strdup_printf("button { background-image: linear-gradient(to bottom, #FF0000, #990000); }");
    gtk_css_provider_load_from_data(provider2, cssData, -1, NULL);
    GtkStyleContext *context = gtk_widget_get_style_context(button);
    gtk_style_context_add_provider(context, GTK_STYLE_PROVIDER(provider2), GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);


    g_signal_connect(button, "clicked", G_CALLBACK(buttonClicked), entry);
    g_signal_connect(entry, "activate", G_CALLBACK(buttonClicked), entry);
    g_signal_connect_swapped(createUserwindow, "destroy", G_CALLBACK(gtk_widget_destroy), createUserwindow);


    gtk_widget_show_all(createUserwindow);

    gtk_main();
}

//connect interface 

void LoginEnvironnement::InterfaceConnect::togglePassword(GtkWidget *widget, gpointer data) {
    GtkWidget *entry = GTK_WIDGET(data);
    if (gtk_entry_get_visibility(GTK_ENTRY(entry))) {
        gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
        gtk_button_set_label(GTK_BUTTON(widget), "Show");
    } else {
        gtk_entry_set_visibility(GTK_ENTRY(entry), TRUE);
        gtk_button_set_label(GTK_BUTTON(widget), "Hide");
    }
}

void LoginEnvironnement::InterfaceConnect::buttonClicked(GtkWidget *widget, gpointer data, gpointer Window) {
    const gchar *entry_text;
    std::string hashpassword;
    entry_text = gtk_entry_get_text(GTK_ENTRY(data));
    std::string password = std::string(entry_text);
    hashpassword = hashFunction(password);
    
    std::string hashReference;
    std::string key = decryptKey();

    std::string hashReferenceCrypted = ReadFromFile("hash_login.bin");
    hashReference = decrypt(hashReferenceCrypted, key);

    memset(&key[0], 0, key.size()); //delete the key from memory after use


   //a delete 

    std::string hashpassword_hex = "";
    for (size_t i = 0; i < hashpassword.size(); ++i) {
        char hex_byte[3];
        snprintf(hex_byte, sizeof(hex_byte), "%02x", static_cast<unsigned char>(hashpassword[i]));
        hashpassword_hex += hex_byte;
    }

    std::string hashReference_hex = "";
    for (size_t i = 0; i < hashReference.size(); ++i) {
        char hex_byte[3];
        snprintf(hex_byte, sizeof(hex_byte), "%02x", static_cast<unsigned char>(hashReference[i]));
        hashReference_hex += hex_byte;
    }

    std::cout << "hashpassword (hex): " << hashpassword_hex << std::endl;
    std::cout << "hashReference (hex): " << hashReference_hex << std::endl;


    // a deletre 


    if (hashpassword == hashReference) { 
        connected=true;       
        gtk_main_quit(); // quitter le main loop de GTK+
    } 
    else {
        std::cout << "Password is incorrect" << std::endl;
    }   
}

void LoginEnvironnement::InterfaceConnect::connectUser(){
    GtkWidget *connectUserwindow;
    GtkWidget *button;
    GtkWidget *entry;
    GtkWidget *grid;
    GtkWidget *vbox;
    GtkWidget *toggleButton;
    GtkCssProvider *provider, *provider2;

    gtk_init(0, NULL);

    connectUserwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(connectUserwindow), 640, 480);
    g_signal_connect(connectUserwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(connectUserwindow), grid);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    GdkRGBA startColor, endColor;
    gdk_rgba_parse(&startColor, "#A5D6A7");
    gdk_rgba_parse(&endColor, "#1B5E20");

    provider = gtk_css_provider_new();
    gchar *cssData = g_strdup_printf("window { background-image: linear-gradient(to bottom, %s, %s); }",
                                      gdk_rgba_to_string(&startColor), gdk_rgba_to_string(&endColor));
    gtk_css_provider_load_from_data(provider, cssData, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    gtk_grid_attach(GTK_GRID(grid), vbox, 1, 1, 1, 1);

    entry = gtk_entry_new();
    gtk_widget_set_size_request(entry, 200, 30); // Ajuster la taille de la zone de texte
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE); // Masquer le texte entré

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    toggleButton = gtk_button_new_with_label("Show");
    gtk_box_pack_end(GTK_BOX(hbox), toggleButton, FALSE, FALSE, 0);

    button = gtk_button_new_with_label("Login");
    gtk_widget_set_size_request(button, 100, 30); // Ajuster la taille du bouton

    provider2 = gtk_css_provider_new();
    cssData = g_strdup_printf("button { background-image: linear-gradient(to bottom, #FF0000, #990000); }");
    gtk_css_provider_load_from_data(provider2, cssData, -1, NULL);
    GtkStyleContext *context = gtk_widget_get_style_context(button);
    gtk_style_context_add_provider(context, GTK_STYLE_PROVIDER(provider2), GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);


    g_signal_connect(button, "clicked", G_CALLBACK(buttonClicked), entry);
    g_signal_connect(entry, "activate", G_CALLBACK(buttonClicked), entry);
    g_signal_connect_swapped(connectUserwindow, "destroy", G_CALLBACK(gtk_widget_destroy), connectUserwindow);

    gtk_widget_show_all(connectUserwindow);

    gtk_main();

}