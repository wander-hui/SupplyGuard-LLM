cmake_minimum_required(VERSION 3.10)
project(vuln_demo)

find_package(OpenSSL 1.0.2 REQUIRED)
find_package(yaml-cpp REQUIRED)

add_executable(vuln vuln.cpp)
target_link_libraries(vuln OpenSSL::SSL yaml-cpp dl)
