# M2354 interface
add_library(m2354iface INTERFACE)

target_include_directories(m2354iface
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CMSIS/Include
        ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/Device/Nuvoton/M2354/Include
        ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/inc
)

# M2354 library
set(src_m2354lib
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/Device/Nuvoton/M2354/Source/ARM/startup_M2354.s
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/Device/Nuvoton/M2354/Source/system_M2354.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/src/retarget.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/src/sys.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/src/clk.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/src/uart.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/StdDriver/src/gpio.c
)

add_library(m2354lib STATIC ${src_m2354lib})

target_link_libraries(m2354lib
    PUBLIC
        m2354iface
)

target_compile_definitions(m2354lib
    PUBLIC
        __MICROLIB
)

target_compile_options(m2354lib PRIVATE
    $<$<COMPILE_LANGUAGE:ASM>: -Wa,--pd,Stack_Size\ EQU\ 0x4000>
)

set(src_cryptacclib
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/aes_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/ccm_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/ecdh_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/ecdsa_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/ecp_internal_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/gcm_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/platform_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/rsa_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/sha256_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator/trng_api.c
)

add_library(cryptacclib STATIC ${src_cryptacclib})

target_compile_definitions(cryptacclib PRIVATE -DMBEDTLS_CONFIG_FILE=<nu_mbedtls_config.h>)

target_include_directories(cryptacclib
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/bsp/Library/CryptoAccelerator
        ${LIB_DIR}/mbedtlslib/include
        ${LIB_DIR}/mbedtlslib/mbedtls/include
        ${LIB_DIR}/mbedtlslib/mbedtls/library
)

target_link_libraries(cryptacclib
    PUBLIC
        m2354iface
)
