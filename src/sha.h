/* Pure C SHA-256/384/512 implementation.
 * Compatible with OpenSSL's SHA256/SHA384/SHA512 output.
 */
#ifndef N2N_SHA_H
#define N2N_SHA_H

#include <stdint.h>
#include <stddef.h>

#define N2N_SHA256_DIGEST_LENGTH  32
#define N2N_SHA384_DIGEST_LENGTH  48
#define N2N_SHA512_DIGEST_LENGTH  64

void n2n_sha256(const uint8_t *data, size_t len, uint8_t *digest);
void n2n_sha384(const uint8_t *data, size_t len, uint8_t *digest);
void n2n_sha512(const uint8_t *data, size_t len, uint8_t *digest);

#endif /* N2N_SHA_H */
