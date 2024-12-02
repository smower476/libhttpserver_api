#include <iostream>
#include <string>
#include <httpserver.hpp>
#include <jwt.h> 
#include <sqlite3.h> 

using namespace httpserver;

const std::string SECRET_KEY = "your_secret_key";

sqlite3* db;

bool open_db(const std::string& db_filename) {
    int rc = sqlite3_open(db_filename.c_str(), &db);
    return rc == SQLITE_OK;
}

void close_db() {
    sqlite3_close(db);
}

void create_tables() {
    const char* user_table_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
    )";

    const char* cart_table_sql = R"(
        CREATE TABLE IF NOT EXISTS cart (
            cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            item_name TEXT,
            quantity INTEGER,
            FOREIGN KEY (username) REFERENCES users(username)
        );
    )";

    char* err_msg = nullptr;

    if (sqlite3_exec(db, user_table_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }

    if (sqlite3_exec(db, cart_table_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
}

bool add_user(const std::string& username, const std::string& password) {
    const std::string sql = "INSERT INTO users (username, password) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool validate_user(const std::string& username, const std::string& password) {
    const std::string sql = "SELECT password FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string stored_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return stored_password == password;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool add_to_cart(const std::string& username, const std::string& item_name, int quantity) {
    const std::string sql = "INSERT INTO cart (username, item_name, quantity) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, item_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, quantity);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

std::string get_cart(const std::string& username) {
    const std::string sql = "SELECT item_name, quantity FROM cart WHERE username = ?;";
    sqlite3_stmt* stmt;
    std::string cart_info = "Cart for " + username + ":\n";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return "";
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* item_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        int quantity = sqlite3_column_int(stmt, 1);
        cart_info += item_name + std::string(" x") + std::to_string(quantity) + "\n";
    }

    sqlite3_finalize(stmt);
    return cart_info.empty() ? "No items in cart." : cart_info;
}

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

class login_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override {
        std::string username = req.get_arg("username");
        std::string password = req.get_arg("password");

        if (validate_user(username, password)) {
            std::string token = create_jwt(username);
            return std::make_shared<string_response>(token, 200, "application/json");
        }

        return std::make_shared<string_response>("Invalid username or password", 401, "text/plain");
    }
};

class validate_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override {
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
};

class cart_resource : public http_resource {
public:
    std::shared_ptr<http_response> render(const http_request& req) override {
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
};

int main() {
    // Open the SQLite database
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

