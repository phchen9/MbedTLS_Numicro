add_executable(helloworld main.c ${TOP_DIR}/src/common/sys_init.c)

target_link_libraries(helloworld
    PRIVATE
        m2354lib
)

target_link_options(helloworld
    PRIVATE
        --library_type=microlib
        --info=sizes,totals
        --symbols
        --map
        --scatter=${TOP_DIR}/scatter/m2354.sct
)

add_custom_command(
    TARGET helloworld
    POST_BUILD
    COMMAND ${ARM_ELF2BIN}
        --bin $<TARGET_FILE:helloworld>
        --output $<TARGET_FILE_DIR:helloworld>/helloworld.bin
)
