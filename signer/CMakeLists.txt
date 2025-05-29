cmake_minimum_required(VERSION 3.16)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
add_executable(signer
    signer.cpp
    handlers.cpp
)
target_link_libraries(signer PRIVATE cbmpc)



