# Copyright (c) 2020-2021 Arm Limited and Contributors. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/Generic-cortex-m-common.cmake)

set(CMAKE_C_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} -g ")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} ${CMAKE_CXX_FLAGS_INIT} ")
set(CMAKE_ASM_FLAGS_INIT "${CMAKE_ASM_FLAGS_INIT} -masm=auto --target=arm-arm-none-eabi -g ")