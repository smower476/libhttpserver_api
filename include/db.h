#ifndef DB_H
#define DB_H

#include <sqlite3.h>
#include <string>
bool open_db(const std::string& db_filename);

void close_db();

void create_tables();

bool add_user(const std::string& username, const std::string& password);

bool validate_user(const std::string& username, const std::string& password);

bool add_to_cart(const std::string& username, const std::string& item_name, int quantity);

std::string get_cart(const std::string& username);

bool delete_user(const std::string& username);

bool update_user_password(const std::string& username, const std::string& new_password);
#endif 
