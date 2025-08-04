add_executable(ecdh main.c ${SRC_DIR}/common/sys_init.c)

target_link_libraries(ecdh
    PRIVATE
        m2354lib
        mbedtlslib
)

target_include_directories(ecdh
    PRIVATE
        ${LIB_DIR}/mbedtlslib/mbedtls/include
)

target_link_options(ecdh
    PRIVATE
        --library_type=microlib
        --info=sizes,totals
        --symbols
        --map
        --scatter=${TOP_DIR}/scatter/m2354.sct
)

add_custom_command(
    TARGET ecdh
    POST_BUILD
    COMMAND ${ARM_ELF2BIN}
        --bin $<TARGET_FILE:ecdh>
        --output $<TARGET_FILE_DIR:ecdh>/ecdh.bin
)
