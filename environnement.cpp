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
#include "cryptography_V2.hpp"
#endif

#ifndef __include_fstream__
#define __include_fstream__
#include <fstream>
#endif

#ifndef __include_gtk__
#define __include_gtk__
#include <gtk-3.0/gtk/gtkx.h>
#include <glib.h>
#endif

using namespace std;

#include "environnement.hpp"

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
    hashpassword = cryptography::HashFunctions::hash_SHA512(password);
    std::string kek_key,aes_key,encrypted_aes_key;

    cryptography::encryption::AES::GENERATE_AES_KEY(aes_key);
    std::string encryptPassword,IV,salt,derivateKey;

    cryptography::encryption::AES::GENERATE_AES_IV(IV);
    cryptography::DerivationKey::generateSalt(salt);
    const int iteration = 100000;
    const int keySize = 32;
    cryptography::DerivationKey::pbkf2Derivation(password,salt,iteration,keySize, derivateKey);

    cryptography::encryption::AES::AES_ENCRYPTION(hashpassword,aes_key,IV,encryptPassword);
    cryptography::encryption::AES::AES_ENCRYPTION(aes_key,derivateKey,IV,encrypted_aes_key);

    cryptography::encryption::AES::generateEnvironnementVariable("aes_key.bin", encrypted_aes_key);
    cryptography::encryption::AES::generateEnvironnementVariable("salt.bin", salt);
    cryptography::encryption::AES::generateEnvironnementVariable("hash_login.bin", encryptPassword);
    
    // Supprimer les données sensibles
    aes_key.clear();
    encrypted_aes_key.clear();
    password.clear();
    derivateKey.clear();
    salt.clear();
    hashpassword.clear();
    encryptPassword.clear();
    IV.clear();
    entry_text = nullptr;
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

    g_signal_connect(toggleButton, "clicked", G_CALLBACK(togglePassword), entry);
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

struct CallbackData {
    GtkWidget *entry;
    GtkWidget *errorLabel;
};

void LoginEnvironnement::InterfaceConnect::buttonClicked(GtkWidget *widget, gpointer data) {
    CallbackData *callbackData = (CallbackData *)data;
    GtkWidget *entry = GTK_WIDGET(callbackData->entry);
    GtkWidget *errorLabel = GTK_WIDGET(callbackData->errorLabel);

    const gchar *entry_text;
    std::string hashpassword;
    entry_text = gtk_entry_get_text(GTK_ENTRY(callbackData->entry));
    std::string password = std::string(entry_text);
    hashpassword = cryptography::HashFunctions::hash_SHA512(password);

    std::string hashReference, salt, aes_key, derivation_key, aes_key_crypted;
    
    salt = cryptography::encryption::AES::ReadFromFile("salt.bin");
    const int iterations = 100000;
    const int key_size = 32;
    cryptography::DerivationKey::pbkf2Derivation(password, salt, iterations, key_size, derivation_key);

    aes_key_crypted = cryptography::encryption::AES::ReadFromFile("aes_key.bin");
    std::string decrypted_aes_key;
    cryptography::encryption::AES::AES_DECRYPTION(aes_key_crypted, derivation_key, decrypted_aes_key);

    std::string hashReferenceCrypted = cryptography::encryption::AES::ReadFromFile("hash_login.bin");
    cryptography::encryption::AES::AES_DECRYPTION(hashReferenceCrypted, decrypted_aes_key, hashReference);

    if (hashpassword == hashReference) {
        connected = true;
        gtk_main_quit(); // Quitter le main loop de GTK+
    } else {
        GtkWidget *errorLabel = callbackData->errorLabel;
        const gchar *errorMessage = "Mot de passe incorrect";
        gtk_label_set_text(GTK_LABEL(errorLabel), errorMessage); // Afficher le message d'erreur sur le GtkLabel
        GdkRGBA redColor;
        gdk_rgba_parse(&redColor, "#FF0000");
        gtk_widget_override_color(errorLabel, GTK_STATE_FLAG_NORMAL, &redColor); // Modifier la couleur du texte en rouge
    }

    // Réinitialiser le texte de l'entrée
    gtk_entry_set_text(GTK_ENTRY(entry), "");

    // Supprimer les données sensibles
    decrypted_aes_key.clear();
    password.clear();
    salt.clear();
    hashpassword.clear();
    hashReferenceCrypted.clear();
    aes_key_crypted.clear();

    memset(const_cast<gchar*>(entry_text), 0, strlen(entry_text)); // Supprimer le texte saisi dans l'espace mémoire
}



GtkWidget* LoginEnvironnement::InterfaceConnect::errorLabel = nullptr;

void LoginEnvironnement::InterfaceConnect::connectUser() {
    GtkWidget *connectUserwindow;
    GtkWidget *button;
    GtkWidget *entry;
    GtkWidget *grid;
    GtkWidget *vbox;
    GtkWidget *toggleButton;
    GtkCssProvider *provider, *provider2;

    // Création des données de rappel
    CallbackData *callbackData = new CallbackData;

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

    callbackData->entry = entry;

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

    // Ajout du GtkLabel pour afficher le message d'erreur
    GtkWidget *errorLabel = gtk_label_new(NULL);
    gtk_box_pack_end(GTK_BOX(vbox), errorLabel, FALSE, FALSE, 0);

    callbackData->errorLabel = errorLabel;

    g_signal_connect(toggleButton, "clicked", G_CALLBACK(togglePassword), callbackData->entry);
    g_signal_connect(button, "clicked", G_CALLBACK(buttonClicked), callbackData);
    g_signal_connect(entry, "activate", G_CALLBACK(buttonClicked), callbackData);
    g_signal_connect_swapped(connectUserwindow, "destroy", G_CALLBACK(gtk_widget_destroy), connectUserwindow);

    gtk_widget_show_all(connectUserwindow);

    gtk_main();
}
