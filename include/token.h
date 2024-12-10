#ifndef JWT_H
#define JWT_H

#include <string>

std::string create_jwt(const std::string& username);

bool validate_jwt(const std::string& token, std::string& username_out);


#endif
