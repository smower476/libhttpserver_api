#include <iostream>
#include <string>
#include "include/routes.h"
#include <httpserver.hpp>
#include "include/db.h"
#include <sodium.h>

#define PORT 8080

using namespace httpserver;


int main() {
    if (!open_db("store.db")) {
        std::cerr << "Can't open database!" << std::endl;
        return 1;
    }

    create_tables();

    webserver ws = create_webserver(PORT);

    login_resource login_res;
    validate_resource validate_res;
    cart_resource cart_res;
    add_user_resource add_user_res;
    delete_user_resource delete_user_res;  
    update_user_resource update_user_res;  
    get_cart_resource get_cart_res; 

    ws.register_resource("/login", &login_res);              // Login endpoint
    ws.register_resource("/validate-token", &validate_res);  // Token validation endpoint
    ws.register_resource("/add-to-cart", &cart_res);         // Add to cart endpoint
    ws.register_resource("/add-user", &add_user_res);        // User creation endpoint
    ws.register_resource("/delete-user", &delete_user_res);  // User deletion endpoint
    ws.register_resource("/update-password", &update_user_res); // Password update endpoint
    ws.register_resource("/get-cart", &get_cart_res);        // Get cart endpoint
    std::cout << "Server running on http://localhost:" << PORT << std::endl;

    ws.start(true);

    close_db();

    return 0;
}


