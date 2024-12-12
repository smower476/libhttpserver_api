#include "../include/regex.h"
#include <iostream>
#include <regex>

bool is_valid_login(const std::string& login) {
    std::regex login_regex("^[a-zA-Z0-9_]{3,20}$");
    return std::regex_match(login, login_regex);
}

bool is_valid_password(const std::string& password) {
    std::regex password_regex("^[a-zA-Z0-9@#%*!?]{8,32}$");
    return std::regex_match(password, password_regex);
}

bool is_valid_jwt(const std::string& token) {
    std::regex jwt_regex(R"(^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$)");
    return std::regex_match(token, jwt_regex);
}
