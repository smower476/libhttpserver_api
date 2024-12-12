#include <jwt.h> 
#include <iostream>
#include "../include/regex.h"

const std::string SECRET_KEY = "your_secret_key";

std::string create_jwt(const std::string& username) {
    jwt_t* jwt = nullptr;
    jwt_new(&jwt);
    jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.size());
    jwt_add_grant(jwt, "username", username.c_str());

    char* encoded_jwt = jwt_encode_str(jwt);
    std::string token(encoded_jwt);

    jwt_free(jwt);
    free(encoded_jwt);

    return token;
}

bool validate_jwt(const std::string& token, std::string& username_out) {
    jwt_t* jwt = nullptr;
    if (!is_valid_jwt(token)){
        return false;
    }
    if (jwt_decode(&jwt, token.c_str(), (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.size()) != 0) {
        return false; // Invalid token
    }

    const char* username = jwt_get_grant(jwt, "username");
    if (username) {
        username_out = std::string(username);
        jwt_free(jwt);
        return true;
    }

    jwt_free(jwt);
    return false;
}
