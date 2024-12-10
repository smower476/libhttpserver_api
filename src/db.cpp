#include "../include/db.h"
#include <iostream>
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


// Delete user
bool delete_user(const std::string& username) {
    // Delete from the cart table first to maintain foreign key integrity
    const std::string delete_cart_sql = "DELETE FROM cart WHERE username = ?;";
    sqlite3_stmt* cart_stmt;

    if (sqlite3_prepare_v2(db, delete_cart_sql.c_str(), -1, &cart_stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare delete cart statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(cart_stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(cart_stmt) != SQLITE_DONE) {
        std::cerr << "Failed to delete from cart: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(cart_stmt);
        return false;
    }

    sqlite3_finalize(cart_stmt);

    const std::string delete_user_sql = "DELETE FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, delete_user_sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare delete user statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to delete user: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

// Update user
bool update_user_password(const std::string& username, const std::string& new_password) {
    const std::string sql = "UPDATE users SET password = ? WHERE username = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_password.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

