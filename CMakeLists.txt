cmake_minimum_required(VERSION 3.5)
project(enc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_executable(deh main.c global.h global.c tpm.h tpm.c)
target_link_libraries(deh tspi crypto)
add_executable(enc encrypt_data.c global.c tpm.c)
target_link_libraries(enc tspi crypto)