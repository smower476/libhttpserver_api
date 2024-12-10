#include <iostream>
#include <string>
#include "include/routes.h"
#include <httpserver.hpp>
#include "include/db.h"


using namespace httpserver;



int main() {
    if (!open_db("store.db")) {
        std::cerr << "Can't open database!" << std::endl;
        return 1;
    }

    create_tables();

    webserver ws = create_webserver(8080);

    login_resource login_res;
    validate_resource validate_res;
    cart_resource cart_res;

    ws.register_resource("/login", &login_res);
    ws.register_resource("/validate-token", &validate_res);
    ws.register_resource("/add-to-cart", &cart_res);

    std::cout << "Server running on http://localhost:8080" << std::endl;

    ws.start(true);

    close_db();

    return 0;
}

