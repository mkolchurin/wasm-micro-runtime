/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

uint64
os_time_get_boot_us()
{
    return k_uptime_get() * 1000;
}

uint64
os_time_thread_cputime_us(void)
{
    /* FIXME if u know the right api */
    return os_time_get_boot_us();
}

int
clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *rqtp,
                struct timespec *rmtp)
{
    k_sleep(K_MSEC(rqtp->tv_sec * 1000 + rqtp->tv_nsec / 1000000));
}