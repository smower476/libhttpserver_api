#include <iostream>
#include <string>
#include <unordered_map>
#include <httpserver.hpp>
#include <jwt.h> // libjwt header

using namespace httpserver;

// Secret key for signing the JWT
const std::string SECRET_KEY = "your_secret_key";

// Simple in-memory user database: username -> password
std::unordered_map<std::string, std::string> users = {
    {"user1", "password1"},
    {"user2", "password2"},
    {"user3", "password3"}
};

// Function to create a JWT token for a user
std::string create_jwt(const std::string& username) {
    jwt_t* jwt = nullptr;

    // Initialize a new JWT object
    jwt_new(&jwt);

    // Set algorithm and claims
    jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.size());
    jwt_add_grant(jwt, "username", username.c_str());

    // Encode the JWT
    char* encoded_jwt = jwt_encode_str(jwt);
    std::string token(encoded_jwt);

    // Free resources
    jwt_free(jwt);
    free(encoded_jwt);

    return token;
}

// Function to validate a JWT token
bool validate_jwt(const std::string& token, std::string& username_out) {
    jwt_t* jwt = nullptr;

    // Decode the JWT
    if (jwt_decode(&jwt, token.c_str(), (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.size()) != 0) {
        return false; // Invalid token
    }

    // Extract the username claim
    const char* username = jwt_get_grant(jwt, "username");
    if (username) {
        username_out = std::string(username);
        jwt_free(jwt);
        return true;
    }

    jwt_free(jwt);
    return false;
}

// HTTP handler for logging in and generating a token
class login_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override {
        // Parse username and password from request body
        std::string username = req.get_arg("username");
        std::string password = req.get_arg("password");

        // Check if user exists and password matches
        if (users.find(username) != users.end() && users[username] == password) {
            std::string token = create_jwt(username);
            return std::make_shared<string_response>(token, 200, "application/json");
        }

        // Invalid credentials
        return std::make_shared<string_response>("Invalid username or password", 401, "text/plain");
    }
};

// HTTP handler for validating a token
class validate_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override {
        // Convert string_view to string
        std::string auth_header = std::string(req.get_header("Authorization"));

        // Extract token from header
        if (auth_header.find("Bearer ") == 0) {
            std::string token = auth_header.substr(7); // Remove "Bearer "

            std::string username;
            if (validate_jwt(token, username)) {
                return std::make_shared<string_response>("Token is valid for user: " + username, 200, "text/plain");
            }
        }

        return std::make_shared<string_response>("Invalid token", 401, "text/plain");
    }
};

// Main function
int main() {
    // Create the HTTP server
    webserver ws = create_webserver(8080);

    // Add resources
    login_resource login_res;
    validate_resource validate_res;

    ws.register_resource("/login", &login_res);
    ws.register_resource("/validate-token", &validate_res);

    std::cout << "Server running on http://localhost:8080" << std::endl;

    // Start the server
    ws.start(true);

    return 0;
}

