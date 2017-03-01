cmake_minimum_required(VERSION 2.8)

project(ShadowHosts)
add_executable(${PROJECT_NAME} "main.cpp" "hostsfile.h" "hostsfile.cpp" "config.h" "config.cpp")
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 14)

find_library(sqlite-cpp NAMES "SQLite++")
target_link_libraries(${PROJECT_NAME} ${sqlite-cpp})

find_library(curl NAMES "curl")
target_link_libraries(${PROJECT_NAME} ${curl})
