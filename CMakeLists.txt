cmake_minimum_required(VERSION 3.5)
project(enc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_executable(create_key create_key.c global.c)
target_link_libraries(create_key tspi crypto)
add_executable(encrypt_data encrypt_data.c global.c)
target_link_libraries(encrypt_data tspi crypto)
add_executable(decrypt_data decrypt_data.c global.c)
target_link_libraries(decrypt_data tspi crypto)