/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

/* function pointers for executable memory management */
static exec_mem_alloc_func_t exec_mem_alloc_func = NULL;
static exec_mem_free_func_t exec_mem_free_func = NULL;

#if WASM_ENABLE_AOT != 0
#ifdef CONFIG_ARM_MPU
/**
 * This function will allow execute from sram region.
 * This is needed for AOT code because by default all soc will
 * disable the execute from SRAM.
 */
static void
disable_mpu_rasr_xn(void)
{
    uint32 index;
    /* Kept the max index as 8 (irrespective of soc) because the sram
       would most likely be set at index 2. */
    for (index = 0U; index < 8; index++) {
        MPU->RNR = index;
        if (MPU->RASR & MPU_RASR_XN_Msk) {
            MPU->RASR |= ~MPU_RASR_XN_Msk;
        }
    }
}
#endif /* end of CONFIG_ARM_MPU */
#endif

static int
_stdout_hook_iwasm(int c)
{
    printk("%c", (char)c);
    return 1;
}

int
os_thread_sys_init();

void
os_thread_sys_destroy();

int
bh_platform_init()
{
    extern void __stdout_hook_install(int (*hook)(int));
    /* Enable printf() in Zephyr */
    __stdout_hook_install(_stdout_hook_iwasm);

#if WASM_ENABLE_AOT != 0
#ifdef CONFIG_ARM_MPU
    /* Enable executable memory support */
    disable_mpu_rasr_xn();
#endif
#endif

    return os_thread_sys_init();
}

void
bh_platform_destroy()
{
    os_thread_sys_destroy();
}

void *
os_malloc(unsigned size)
{
    return NULL;
}

void *
os_realloc(void *ptr, unsigned size)
{
    return NULL;
}

void
os_free(void *ptr)
{
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

#if 0
struct out_context {
    int count;
};

typedef int (*out_func_t)(int c, void *ctx);

static int
char_out(int c, void *ctx)
{
    struct out_context *out_ctx = (struct out_context*)ctx;
    out_ctx->count++;
    return _stdout_hook_iwasm(c);
}

int
os_vprintf(const char *fmt, va_list ap)
{
#if 0
    struct out_context ctx = { 0 };
    cbvprintf(char_out, &ctx, fmt, ap);
    return ctx.count;
#else
    vprintk(fmt, ap);
    return 0;
#endif
}
#endif

int
os_printf(const char *format, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, format);
#ifndef BH_VPRINTF
    ret += vprintf(format, ap);
#else
    ret += BH_VPRINTF(format, ap);
#endif
    va_end(ap);

    return ret;
}

int
os_vprintf(const char *format, va_list ap)
{
#ifndef BH_VPRINTF
    return vprintf(format, ap);
#else
    return BH_VPRINTF(format, ap);
#endif
}

#if KERNEL_VERSION_NUMBER <= 0x020400 /* version 2.4.0 */
void
abort(void)
{
    int i = 0;
    os_printf("%d\n", 1 / i);
}
#endif

#if KERNEL_VERSION_NUMBER <= 0x010E01 /* version 1.14.1 */
size_t
strspn(const char *s, const char *accept)
{
    os_printf("## unimplemented function %s called", __FUNCTION__);
    return 0;
}

size_t
strcspn(const char *s, const char *reject)
{
    os_printf("## unimplemented function %s called", __FUNCTION__);
    return 0;
}
#endif

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    if ((uint64)size >= UINT32_MAX)
        return NULL;
    if (exec_mem_alloc_func)
        return exec_mem_alloc_func((uint32)size);
    else
        return BH_MALLOC(size);
}

void
os_munmap(void *addr, size_t size)
{
    if (exec_mem_free_func)
        exec_mem_free_func(addr);
    else
        BH_FREE(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{
#if defined(CONFIG_CPU_CORTEX_M7) && defined(CONFIG_ARM_MPU)
    uint32 key;
    key = irq_lock();
    SCB_CleanDCache();
    irq_unlock(key);
#elif defined(CONFIG_SOC_CVF_EM7D) && defined(CONFIG_ARC_MPU) \
    && defined(CONFIG_CACHE_FLUSHING)
    __asm__ __volatile__("sync");
    z_arc_v2_aux_reg_write(_ARC_V2_DC_FLSH, BIT(0));
    __asm__ __volatile__("sync");
#endif
}

void
os_icache_flush(void *start, size_t len)
{
}

void
set_exec_mem_alloc_func(exec_mem_alloc_func_t alloc_func,
                        exec_mem_free_func_t free_func)
{
    exec_mem_alloc_func = alloc_func;
    exec_mem_free_func = free_func;
}

ssize_t
writev(int fildes, const struct iovec *iov, int iovcnt)
{
    ssize_t ntotal;
    ssize_t nwritten;
    size_t remaining;
    uint8_t *buffer;
    int i;

    /* Process each entry in the struct iovec array */

    for (i = 0, ntotal = 0; i < iovcnt; i++) {
        /* Ignore zero-length writes */

        if (iov[i].iov_len > 0) {
            buffer = iov[i].iov_base;
            remaining = iov[i].iov_len;

            /* Write repeatedly as necessary to write the entire buffer */

            do {
                /* NOTE:  write() is a cancellation point */

                nwritten = write(fildes, buffer, remaining);

                /* Check for a write error */

                if (nwritten < 0) {
                    return ntotal ? ntotal : -1;
                }

                /* Update pointers and counts in order to handle partial
                 * buffer writes.
                 */

                buffer += nwritten;
                remaining -= nwritten;
                ntotal += nwritten;
            } while (remaining > 0);
        }
    }

    return ntotal;
}

__wasi_errno_t
os_fstat(os_file_handle handle, struct __wasi_filestat_t *buf)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_fstatat(os_file_handle handle, const char *path,
           struct __wasi_filestat_t *buf, __wasi_lookupflags_t lookup_flags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_file_get_fdflags(os_file_handle handle, __wasi_fdflags_t *flags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_file_set_fdflags(os_file_handle handle, __wasi_fdflags_t flags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_fdatasync(os_file_handle handle)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_fsync(os_file_handle handle)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_open_preopendir(const char *path, os_file_handle *out)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_openat(os_file_handle handle, const char *path, __wasi_oflags_t oflags,
          __wasi_fdflags_t fd_flags, __wasi_lookupflags_t lookup_flags,
          wasi_libc_file_access_mode access_mode, os_file_handle *out)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_file_get_access_mode(os_file_handle handle,
                        wasi_libc_file_access_mode *access_mode)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_close(os_file_handle handle, bool is_stdio)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_preadv(os_file_handle handle, const struct __wasi_iovec_t *iov, int iovcnt,
          __wasi_filesize_t offset, size_t *nread)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_pwritev(os_file_handle handle, const struct __wasi_ciovec_t *iov, int iovcnt,
           __wasi_filesize_t offset, size_t *nwritten)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_readv(os_file_handle handle, const struct __wasi_iovec_t *iov, int iovcnt,
         size_t *nread)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_writev(os_file_handle handle, const struct __wasi_ciovec_t *iov, int iovcnt,
          size_t *nwritten)
{
    return 0;
}

__wasi_errno_t
os_fallocate(os_file_handle handle, __wasi_filesize_t offset,
             __wasi_filesize_t length)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_ftruncate(os_file_handle handle, __wasi_filesize_t size)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_futimens(os_file_handle handle, __wasi_timestamp_t access_time,
            __wasi_timestamp_t modification_time, __wasi_fstflags_t fstflags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_utimensat(os_file_handle handle, const char *path,
             __wasi_timestamp_t access_time,
             __wasi_timestamp_t modification_time, __wasi_fstflags_t fstflags,
             __wasi_lookupflags_t lookup_flags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_readlinkat(os_file_handle handle, const char *path, char *buf,
              size_t bufsize, size_t *nread)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_linkat(os_file_handle from_handle, const char *from_path,
          os_file_handle to_handle, const char *to_path,
          __wasi_lookupflags_t lookup_flags)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_symlinkat(const char *old_path, os_file_handle handle, const char *new_path)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_mkdirat(os_file_handle handle, const char *path)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_renameat(os_file_handle old_handle, const char *old_path,
            os_file_handle new_handle, const char *new_path)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_unlinkat(os_file_handle handle, const char *path, bool is_dir)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_lseek(os_file_handle handle, __wasi_filedelta_t offset,
         __wasi_whence_t whence, __wasi_filesize_t *new_offset)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_fadvise(os_file_handle handle, __wasi_filesize_t offset,
           __wasi_filesize_t length, __wasi_advice_t advice)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_isatty(os_file_handle handle)
{
    return __WASI_ENOTSUP;
}

os_file_handle
os_convert_stdin_handle(os_raw_file_handle raw_stdin)
{
    return __WASI_ENOTSUP;
}

os_file_handle
os_convert_stdout_handle(os_raw_file_handle raw_stdout)
{
    return __WASI_ENOTSUP;
}

os_file_handle
os_convert_stderr_handle(os_raw_file_handle raw_stderr)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_fdopendir(os_file_handle handle, os_dir_stream *dir_stream)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_rewinddir(os_dir_stream dir_stream)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_seekdir(os_dir_stream dir_stream, __wasi_dircookie_t position)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_readdir(os_dir_stream dir_stream, __wasi_dirent_t *entry,
           const char **d_name)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_closedir(os_dir_stream dir_stream)
{
    return __WASI_ENOTSUP;
}

os_dir_stream
os_get_invalid_dir_stream()
{
    return NULL;
}

bool
os_is_dir_stream_valid(os_dir_stream *dir_stream)
{
    return false;
}

// os_file_handle
// os_get_invalid_handle()
//{
//     return -1;
// }

bool
os_is_handle_valid(os_file_handle *handle)
{
    return false;
}

char *
os_realpath(const char *path, char *resolved_path)
{
    return NULL;
}

__wasi_errno_t
os_clock_res_get(__wasi_clockid_t clock_id, __wasi_timestamp_t *resolution)
{
    return __WASI_ENOTSUP;
}

__wasi_errno_t
os_clock_time_get(__wasi_clockid_t clock_id, __wasi_timestamp_t precision,
                  __wasi_timestamp_t *time)
{
    return __WASI_ENOTSUP;
}

/****************************************************
 *                     Section 2                    *
 *                   Socket support                 *
 ****************************************************/

int
os_socket_create(bh_socket_t *sock, bool is_ipv4, bool is_tcp)
{
    return -1;
}

int
os_socket_bind(bh_socket_t socket, const char *addr, int *port)
{
    return -1;
}

int
os_socket_settimeout(bh_socket_t socket, uint64 timeout_us)
{
    return -1;
}

int
os_socket_listen(bh_socket_t socket, int max_client)
{
    return -1;
}

int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen)
{
    return -1;
}

int
os_socket_connect(bh_socket_t socket, const char *addr, int port)
{
    return -1;
}

int
os_socket_recv(bh_socket_t socket, void *buf, unsigned int len)
{
    return -1;
}

int
os_socket_recv_from(bh_socket_t socket, void *buf, unsigned int len, int flags,
                    bh_sockaddr_t *src_addr)
{
    return -1;
}

int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len)
{
    return -1;
}

int
os_socket_send_to(bh_socket_t socket, const void *buf, unsigned int len,
                  int flags, const bh_sockaddr_t *dest_addr)
{
    return -1;
}

int
os_socket_close(bh_socket_t socket)
{
    return -1;
}

__wasi_errno_t
os_socket_shutdown(bh_socket_t socket)
{
    return __WASI_ENOTSUP;
}

int
os_socket_inet_network(bool is_ipv4, const char *cp, bh_ip_addr_buffer_t *out)
{
    return -1;
}

int
os_socket_addr_resolve(const char *host, const char *service,
                       uint8_t *hint_is_tcp, uint8_t *hint_is_ipv4,
                       bh_addr_info_t *addr_info, size_t addr_info_size,
                       size_t *max_info_size)
{
    return -1;
}

int
os_socket_addr_local(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    return -1;
}

int
os_socket_addr_remote(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    return -1;
}

int
os_socket_set_send_buf_size(bh_socket_t socket, size_t bufsiz)
{
    return -1;
}

int
os_socket_get_send_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    return -1;
}

int
os_socket_set_recv_buf_size(bh_socket_t socket, size_t bufsiz)
{
    return -1;
}

int
os_socket_get_recv_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    return -1;
}

int
os_socket_set_keep_alive(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_keep_alive(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_send_timeout(bh_socket_t socket, uint64 timeout_us)
{
    return -1;
}

int
os_socket_get_send_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    return -1;
}

int
os_socket_set_recv_timeout(bh_socket_t socket, uint64 timeout_us)
{
    return -1;
}

int
os_socket_get_recv_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    return -1;
}

int
os_socket_set_reuse_addr(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_reuse_addr(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_reuse_port(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_reuse_port(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_linger(bh_socket_t socket, bool is_enabled, int linger_s)
{
    return -1;
}

int
os_socket_get_linger(bh_socket_t socket, bool *is_enabled, int *linger_s)
{
    return -1;
}

int
os_socket_set_tcp_no_delay(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_tcp_no_delay(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_tcp_quick_ack(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_tcp_quick_ack(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_tcp_keep_idle(bh_socket_t socket, uint32_t time_s)
{
    return -1;
}

int
os_socket_get_tcp_keep_idle(bh_socket_t socket, uint32_t *time_s)
{
    return -1;
}

int
os_socket_set_tcp_keep_intvl(bh_socket_t socket, uint32_t time_s)
{
    return -1;
}

int
os_socket_get_tcp_keep_intvl(bh_socket_t socket, uint32_t *time_s)
{
    return -1;
}

int
os_socket_set_tcp_fastopen_connect(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_tcp_fastopen_connect(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool is_enabled)
{
    return -1;
}

int
os_socket_get_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_ip_add_membership(bh_socket_t socket,
                                bh_ip_addr_buffer_t *imr_multiaddr,
                                uint32_t imr_interface, bool is_ipv6)
{
    return -1;
}

int
os_socket_set_ip_drop_membership(bh_socket_t socket,
                                 bh_ip_addr_buffer_t *imr_multiaddr,
                                 uint32_t imr_interface, bool is_ipv6)
{
    return -1;
}

int
os_socket_set_ip_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    return -1;
}

int
os_socket_get_ip_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    return -1;
}

int
os_socket_set_ip_multicast_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    return -1;
}

int
os_socket_get_ip_multicast_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    return -1;
}

int
os_socket_set_ipv6_only(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_ipv6_only(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}

int
os_socket_set_broadcast(bh_socket_t socket, bool is_enabled)
{
    return -1;
}

int
os_socket_get_broadcast(bh_socket_t socket, bool *is_enabled)
{
    return -1;
}
