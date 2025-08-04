cmake_minimum_required(VERSION 3.21)

project(mbedtls_numicro LANGUAGES C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(TOP_DIR ${PROJECT_SOURCE_DIR})
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(lib/m2354lib)
add_subdirectory(lib/mbedtlslib)
add_subdirectory(src/helloworld)
add_subdirectory(src/ecdsa)
add_subdirectory(src/ecdh)
