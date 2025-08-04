# Copyright (c) 2020-2021 Arm Limited and Contributors. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Set CMAKE_MODULE_PATH so CMake can find our platform files
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/Modules" ${CMAKE_MODULE_PATH})

# the name of the target operating system
set(CMAKE_SYSTEM_NAME Generic)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# which compilers to use for ASM, C and C++
set(CMAKE_ASM_COMPILER "armclang")
set(CMAKE_C_COMPILER "armclang")
set(CMAKE_CXX_COMPILER "armclang")

set(CMAKE_AR "armar")
set(ARM_ELF2BIN "fromelf")
set_property(GLOBAL PROPERTY ELF2BIN ${ARM_ELF2BIN})

# Tell CMake about compiler targets. This will cause CMake to add the --target
# flag.
set(CMAKE_C_COMPILER_TARGET arm-arm-none-eabi)
set(CMAKE_CXX_COMPILER_TARGET arm-arm-none-eabi)