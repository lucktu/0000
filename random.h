/**
 * @brief Random number generation for n2n
 *
 * Uses cryptographically secure random sources:
 *   - Windows: BCryptGenRandom
 *   - Linux: getrandom() or /dev/urandom
 *   - BSD/macOS: getentropy() or /dev/urandom
 */

#ifndef N2N_RANDOM_H_
#define N2N_RANDOM_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <unistd.h>
#include <sys/random.h>
#include <errno.h>
#include <fcntl.h>
#endif

/* ---------- random_bytes: fill buffer with cryptographically secure random bytes ---------- */
static inline int random_bytes_buf(uint8_t *buf, size_t n) {
    if (n == 0) return 0;

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;

#elif defined(__linux__)
    /* Try getrandom() first (Linux 3.17+) */
    size_t done;
#if defined(SYS_getrandom)
    done = 0;
    while (done < n) {
        ssize_t ret = syscall(SYS_getrandom, buf + done, n - done, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        done += (size_t)ret;
    }
    if (done == n) return 0;
#endif
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    done = 0;
    while (done < n) {
        ssize_t ret = read(fd, buf + done, n - done);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)ret;
    }
    close(fd);
    return 0;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    /* Try getentropy() first (OpenBSD 5.6+, FreeBSD 12.0+, macOS 10.12+) */
    size_t done;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    done = 0;
    while (done < n) {
        size_t chunk = (n - done > 256) ? 256 : (n - done);
        if (getentropy(buf + done, chunk) != 0) {
            break;
        }
        done += chunk;
    }
    if (done == n) return 0;
#endif
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    done = 0;
    while (done < n) {
        ssize_t ret = read(fd, buf + done, n - done);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)ret;
    }
    close(fd);
    return 0;

#else
    /* Unknown platform: try /dev/urandom as last resort */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < n) {
        ssize_t ret = read(fd, buf + done, n - done);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)ret;
    }
    close(fd);
    return 0;
#endif
}

/* ---------- Compatibility shim for old callers using random_ctx_t ---------- */
struct random_ctx { int _unused; };  /* empty struct */
typedef struct random_ctx *random_ctx_t;

static inline void random_init(random_ctx_t ctx) {
    (void)ctx;
    /* No initialization needed - we use system CSPRNG */
}
static inline void random_free(random_ctx_t ctx) { (void)ctx; }

static inline void random_bytes(random_ctx_t ctx, uint8_t *buf, size_t n) {
    (void)ctx;
    if (random_bytes_buf(buf, n) != 0) {
        /* Fatal error: cannot generate secure random bytes */
        abort();
    }
}

/* ---------- Fast non-cryptographic PRNG for IV generation ----------
 * Uses xorshift64* to avoid expensive getrandom() syscalls on every packet.
 * Security: IV only needs uniqueness (not secrecy), xorshift64 is sufficient. */
static inline uint64_t fast_rand64(void) {
    static uint64_t state = 0;
    if (state == 0) {
        /* One-time seed from CSPRNG */
        random_bytes_buf((uint8_t*)&state, 8);
        if (state == 0) state = 1;
    }
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545F4914F6CDD1DULL;
}

/* Fill buf with n bytes from fast PRNG */
static inline void fast_rand_bytes(uint8_t *buf, size_t n) {
    size_t i;
    for (i = 0; i + 8 <= n; i += 8) {
        uint64_t r = fast_rand64();
        memcpy(buf + i, &r, 8);
    }
    if (i < n) {
        uint64_t r = fast_rand64();
        memcpy(buf + i, &r, n - i);
    }
}

#endif /* N2N_RANDOM_H_ */
