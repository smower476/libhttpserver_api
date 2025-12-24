#include <httplib.h>
#include <pqxx/pqxx>
#include <iostream>
#include <cstdlib>

using namespace std;

// Функция для получения строки подключения из переменных окружения
string get_db_conn_str() {
    return "host=" + string(getenv("DB_HOST")) +
           " port=" + string(getenv("DB_PORT")) +
           " dbname=" + string(getenv("DB_NAME")) +
           " user=" + string(getenv("DB_USER")) +
           " password=" + string(getenv("DB_PASSWORD"));
}

int main() {
    httplib::Server svr;

    // Обработка GET запроса - получение списка имен
    svr.Get("/items", [](const httplib::Request&, httplib::Response& res) {
        try {
            pqxx::connection c(get_db_conn_str());
            pqxx::work txn(c);
            pqxx::result r = txn.exec("SELECT name FROM items");

            string out = "Items in DB:\n";
            for (auto row : r) {
                out += "- " + row[0].as<string>() + "\n";
            }
            res.set_content(out, "text/plain");
        } catch (const exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // Обработка POST запроса - добавление элемента
    svr.Post("/add", [](const httplib::Request& req, httplib::Response& res) {
        string name = req.get_param_value("name");
        if (name.empty()) {
            res.status = 400;
            res.set_content("Missing 'name' parameter", "text/plain");
            return;
        }

        try {
            pqxx::connection c(get_db_conn_str());
            pqxx::work txn(c);
            txn.exec_params("INSERT INTO items (name) VALUES ($1)", name);
            txn.commit();
            res.set_content("Added: " + name, "text/plain");
        } catch (const exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    cout << "Server started at http://0.0.0.0:8080" << endl;
    svr.listen("0.0.0.0", 8080);
    return 0;
}
