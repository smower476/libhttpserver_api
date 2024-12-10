#include "../include/routes.h"

std::shared_ptr<http_response> login_resource::render(const http_request& req) {
    std::string username = req.get_arg("username");
    std::string password = req.get_arg("password");

    if (validate_user(username, password)) {
        std::string token = create_jwt(username);
        return std::make_shared<string_response>(token, 200, "application/json");
    }

    return std::make_shared<string_response>("Invalid username or password", 401, "text/plain");
}

std::shared_ptr<http_response> validate_resource::render(const http_request& req) {
    std::string auth_header = std::string(req.get_header("Authorization"));

    if (auth_header.find("Bearer ") == 0) {
        std::string token = auth_header.substr(7); // Remove "Bearer "

        std::string username;
        if (validate_jwt(token, username)) {
            return std::make_shared<string_response>("Token is valid for user: " + username, 200, "text/plain");
        }
    }

    return std::make_shared<string_response>("Invalid token", 401, "text/plain");
}

std::shared_ptr<http_response> cart_resource::render(const http_request& req) {
    std::string auth_header = std::string(req.get_header("Authorization"));

    if (auth_header.find("Bearer ") == 0) {
        std::string token = auth_header.substr(7); // Remove "Bearer "
        std::string username;

        if (validate_jwt(token, username)) {
            std::string item_name = req.get_arg("item_name");
            int quantity = std::stoi(req.get_arg("quantity"));
            if (add_to_cart(username, item_name, quantity)) {
                return std::make_shared<string_response>("Item added to cart", 200, "text/plain");
            }
        }
    }

    return std::make_shared<string_response>("Failed to add item", 400, "text/plain");
}

