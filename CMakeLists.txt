cmake_minimum_required(VERSION 3.5)
project(enc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_executable(createKey createKey.c global.c)
target_link_libraries(createKey tspi)
add_executable(enc main.c)
target_link_libraries(enc crypto)