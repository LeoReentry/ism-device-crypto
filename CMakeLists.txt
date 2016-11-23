cmake_minimum_required(VERSION 3.5)
project(enc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_executable(deh main.c global.c)
target_link_libraries(deh tspi crypto)