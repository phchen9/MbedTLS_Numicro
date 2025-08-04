# Copyright (c) 2020-2022 Arm Limited and Contributors. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/Generic-ARMClang-cortex-m-common.cmake)

set(CMAKE_ASM_FLAGS_INIT "${CMAKE_ASM_FLAGS_INIT} -mcpu=cortex-m23 -mfloat-abi=soft")