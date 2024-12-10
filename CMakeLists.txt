cmake_minimum_required(VERSION 3.15)
project(api)
 
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE "Release")
 
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBHTTPSERVER REQUIRED libhttpserver)
pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd)
pkg_check_modules(LIBJWT REQUIRED libjwt)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
 
add_executable(server main.cpp src/db.cpp src/token.cpp src/routes.cpp)
 
 
target_include_directories(server PRIVATE ${LIBHTTPSERVER_INCLUDE_DIRS} ${LIBMICROHTTPD_INCLUDE_DIRS} ${LIBJWT_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(server PRIVATE ${LIBHTTPSERVER_LIBRARIES} ${LIBMICROHTTPD_LIBRARIES} ${LIBJWT_LIBRARIES} ${SQLITE3_LIBRARIES})
link_directories(${LIBHTTPSERVER_LIBRARY_DIRS} ${LIBMICROHTTPD_LIBRARY_DIRS} ${LIBJWT_LIBRARY_DIRS} ${SQLITE3_LIBRARY_DIRS})
 
target_compile_definitions(server PRIVATE ${LIBHTTPSERVER_CFLAGS_OTHER} ${LIBMICROHTTPD_CFLAGS_OTHER} ${LIBJWT_CFLAGS_OTHER} ${SQLITE3_CFLAGS_OTHER})

