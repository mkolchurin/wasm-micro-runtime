# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_ZEPHYR)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

# file(GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

# include (${CMAKE_CURRENT_LIST_DIR}/../common/math/platform_api_math.cmake)
# include(${CMAKE_CURRENT_LIST_DIR}/../common/libc-util/platform_common_libc_util.cmake)
# include (${CMAKE_CURRENT_LIST_DIR}/../common/posix/platform_api_posix.cmake)
file(GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

if(WAMR_BUILD_LIBC_WASI EQUAL 1)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_blocking_op.c)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_clock.c)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_file.c)
	#list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_malloc.c)

	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_sleep.c)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_socket.c)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_thread.c)
	list(APPEND source_all ${PLATFORM_SHARED_DIR}/../common/posix/posix_time.c)

	include(${CMAKE_CURRENT_LIST_DIR}/../common/libc-util/platform_common_libc_util.cmake)
	set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
endif()

# set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
set(PLATFORM_SHARED_SOURCE ${source_all} ${PLATFORM_COMMON_POSIX_SOURCE})

# set(PLATFORM_SHARED_SOURCE ${source_all}) # ${PLATFORM_COMMON_MATH_SOURCE})
