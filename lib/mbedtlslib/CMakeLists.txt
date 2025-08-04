# Starting Mbed TLS 3.x release, mbedtls/library/CMakeLists.txt has dependency on
# link_to_source() function that is in mbedtls/CMakeLists.txt, so define
# link_to_source here. This shall be later expanded to add a link to the mbedtls
# source file from the build directory if required by libspdm.
function(link_to_source base_name)
endfunction(link_to_source)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/mbedtls/library)

# mbedtls
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedtls PRIVATE -DMBEDTLS_CONFIG_FILE=<nu_mbedtls_config.h>)
endif()
target_include_directories(mbedtls PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

target_link_libraries(mbedtls
    PRIVATE
        cryptacclib
)

# mbedx509
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedx509 PRIVATE -DMBEDTLS_CONFIG_FILE=<nu_mbedtls_config.h>)
endif()
target_include_directories(mbedx509 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

target_link_libraries(mbedx509
    PRIVATE
        cryptacclib
)

# mbedcrypto
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedcrypto PRIVATE -DMBEDTLS_CONFIG_FILE=<nu_mbedtls_config.h>)
endif()
target_include_directories(mbedcrypto PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

target_link_libraries(mbedcrypto
    PRIVATE
        cryptacclib
)

add_library(mbedtlslib INTERFACE)
target_link_libraries(mbedtlslib INTERFACE
    mbedx509
    mbedcrypto
)