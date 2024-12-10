#ifndef ROUTES_H
#define ROUTES_H

#include "db.h"
#include <httpserver.hpp>
#include <string>
#include <memory>

// External utility functions
bool validate_user(const std::string& username, const std::string& password);
std::string create_jwt(const std::string& username);
bool validate_jwt(const std::string& token, std::string& username_out);
bool add_to_cart(const std::string& username, const std::string& item_name, int quantity);

using namespace httpserver;

class login_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class validate_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class cart_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class delete_user_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class update_user_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class add_user_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

class get_cart_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override;
};

#endif // ROUTES_H

