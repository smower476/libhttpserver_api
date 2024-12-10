#include "../include/routes.h"
#include "../include/db.h"
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

// Add to cart
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

// Delete a user
std::shared_ptr<http_response> delete_user_resource::render(const http_request& req) {
    std::string username = req.get_arg("username");

    if (delete_user(username)) {
        return std::make_shared<string_response>("User deleted successfully", 200, "text/plain");
    }

    return std::make_shared<string_response>("User deletion failed", 400, "text/plain");
}

// Update user password
std::shared_ptr<http_response> update_user_resource::render(const http_request& req) {
    std::string username = req.get_arg("username");
    std::string new_password = req.get_arg("new_password");

    if (update_user_password(username, new_password)) {
        return std::make_shared<string_response>("Password updated successfully", 200, "text/plain");
    }

    return std::make_shared<string_response>("Password update failed", 400, "text/plain");
}

std::shared_ptr<http_response> add_user_resource::render(const http_request& req) {
    std::string username = req.get_arg("username");
    std::string password = req.get_arg("password");

    if (add_user(username, password)) {
        return std::make_shared<string_response>("User created successfully", 201, "text/plain");
    }

    return std::make_shared<string_response>("User creation failed", 400, "text/plain");
}

std::shared_ptr<http_response> get_cart_resource::render(const http_request& req) {
        std::string auth_header = std::string(req.get_header("Authorization"));

        if (auth_header.find("Bearer ") == 0) {
            std::string token = auth_header.substr(7); // Remove "Bearer "
            std::string username;

            if (validate_jwt(token, username)) {
                std::string cart = get_cart(username);
                return std::make_shared<string_response>(cart, 200, "text/plain");
            }
        }

        return std::make_shared<string_response>("Unauthorized or invalid token", 401, "text/plain");
    }
