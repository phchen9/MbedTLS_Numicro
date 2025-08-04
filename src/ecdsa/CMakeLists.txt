add_executable(ecdsa main.c ${SRC_DIR}/common/sys_init.c)

target_link_libraries(ecdsa
    PRIVATE
        m2354lib
        mbedtlslib
)

target_include_directories(ecdsa
    PRIVATE
        ${LIB_DIR}/mbedtlslib/mbedtls/include
)

target_link_options(ecdsa
    PRIVATE
        --library_type=microlib
        --info=sizes,totals
        --symbols
        --map
        --scatter=${TOP_DIR}/scatter/m2354.sct
)

add_custom_command(
    TARGET ecdsa
    POST_BUILD
    COMMAND ${ARM_ELF2BIN}
        --bin $<TARGET_FILE:ecdsa>
        --output $<TARGET_FILE_DIR:ecdsa>/ecdsa.bin
)
