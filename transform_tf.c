/* (c) 2009 Richard Andrews <andrews@ntop.org>
 * Simplified Twofish transform — single-key, no SA array, stack buffer.
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "twofish.h"
#include "random.h"

#define N2N_TWOFISH_TRANSFORM_VERSION   1  /* version of the transform encoding */

/** Twofish transform state data — single-key preshared setup. */
typedef struct transop_tf {
    TWOFISH *enc_tf;  /* tx state */
    TWOFISH *dec_tf;  /* rx state */
    uint8_t  assembly[N2N_TRANSFORM_BUF_SIZE]; /* encode workspace (bypass LAN KCP needs >4KB) */
} transop_tf_t;

static int transop_deinit_twofish(n2n_trans_op_t *arg) {
    transop_tf_t *priv = (transop_tf_t *)arg->priv;
    if (priv) {
        TwoFishDestroy(priv->enc_tf);
        TwoFishDestroy(priv->dec_tf);
        free(priv);
    }
    arg->priv = NULL;
    return 0;
}

#define TRANSOP_TF_VER_SIZE     1
#define TRANSOP_TF_NONCE_SIZE   4
#define TRANSOP_TF_SA_SIZE      4

/** The twofish packet format (unchanged, wire-compatible):
 *  [V|SSSS|nnnn|DDDDDDDDDDDDDDDDDDDDD]
 *         |<---- encrypted ---->|
 */
static ssize_t transop_encode_twofish(n2n_trans_op_t *arg,
                                      uint8_t *outbuf, size_t out_len,
                                      const uint8_t *inbuf, size_t in_len,
                                      const uint8_t *peer_mac) {
    ssize_t len = -1;
    transop_tf_t *priv = (transop_tf_t *)arg->priv;

    if ((in_len + TRANSOP_TF_NONCE_SIZE) <= N2N_TRANSFORM_BUF_SIZE) {
        if ((in_len + TRANSOP_TF_NONCE_SIZE + TRANSOP_TF_SA_SIZE + TRANSOP_TF_VER_SIZE) <= out_len) {
            size_t idx = 0;

            traceEvent(TRACE_DEBUG, "encode_twofish %lu", in_len);

            encode_uint8(outbuf, &idx, N2N_TWOFISH_TRANSFORM_VERSION);
            encode_uint32(outbuf, &idx, 0); /* SA always 0 for preshared key */

            *(uint32_t *)priv->assembly = (uint32_t)fast_rand64();
            memcpy(priv->assembly + TRANSOP_TF_NONCE_SIZE, inbuf, in_len);

            len = TwoFishEncryptRaw(priv->assembly,
                                    outbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE,
                                    in_len + TRANSOP_TF_NONCE_SIZE,
                                    priv->enc_tf);
            if (len > 0)
                len += TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE;
            else
                traceEvent(TRACE_ERROR, "encode_twofish encryption failed.");
        } else {
            traceEvent(TRACE_ERROR, "encode_twofish outbuf too small.");
        }
    } else {
        traceEvent(TRACE_ERROR, "encode_twofish inbuf too big to encrypt.");
    }
    return len;
}

static ssize_t transop_decode_twofish(n2n_trans_op_t *arg,
                                      uint8_t *outbuf, size_t out_len,
                                      const uint8_t *inbuf, size_t in_len,
                                      const uint8_t *peer_mac) {
    size_t len = 0;
    transop_tf_t *priv = (transop_tf_t *)arg->priv;

    if (((in_len - (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE)) <= N2N_TRANSFORM_BUF_SIZE)
     && (in_len >= (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE + TRANSOP_TF_NONCE_SIZE))) {
        size_t rem = in_len, idx = 0;
        uint8_t tf_enc_ver = 0;
        uint32_t sa_rx = 0;

        decode_uint8(&tf_enc_ver, inbuf, &rem, &idx);
        if (N2N_TWOFISH_TRANSFORM_VERSION == tf_enc_ver) {
            decode_uint32(&sa_rx, inbuf, &rem, &idx); /* SA ignored, single-key */

            traceEvent(TRACE_DEBUG, "decode_twofish %lu", in_len);

            /* Decrypt directly to outbuf — skip assembly, saves one copy */
            len = TwoFishDecryptRaw((uint8_t *)(inbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE),
                                    outbuf,
                                    in_len - (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE),
                                    priv->dec_tf);
            if (len > 0) {
                len -= TRANSOP_TF_NONCE_SIZE;
                memmove(outbuf, outbuf + TRANSOP_TF_NONCE_SIZE, len);
            } else {
                traceEvent(TRACE_ERROR, "decode_twofish decryption failed.");
            }
        } else {
            traceEvent(TRACE_ERROR, "decode_twofish unsupported version %u.", tf_enc_ver);
        }
    } else {
        traceEvent(TRACE_ERROR, "decode_twofish inbuf wrong size (%ul).", in_len);
    }
    return len;
}

static int transop_addspec_twofish(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) {
    return 0; /* single-key, no dynamic SA */
}

static n2n_tostat_t transop_tick_twofish(n2n_trans_op_t *arg, time_t now) {
    n2n_tostat_t r;
    memset(&r, 0, sizeof(r));
    r.can_tx = 1;
    r.tx_spec.t = N2N_TRANSFORM_ID_TWOFISH;
    return r;
}

int transop_twofish_setup(n2n_trans_op_t *ttt,
                          n2n_sa_t sa_num,
                          uint8_t *encrypt_pwd,
                          uint64_t encrypt_pwd_len) {
    if (ttt->priv)
        transop_deinit_twofish(ttt);

    memset(ttt, 0, sizeof(n2n_trans_op_t));

    transop_tf_t *priv = (transop_tf_t *)malloc(sizeof(transop_tf_t));
    if (!priv) {
        traceEvent(TRACE_ERROR, "Failed to allocate priv for twofish");
        return 1;
    }

    priv->enc_tf = TwoFishInit(encrypt_pwd, encrypt_pwd_len);
    priv->dec_tf = TwoFishInit(encrypt_pwd, encrypt_pwd_len);

    if (!priv->enc_tf || !priv->dec_tf) {
        if (priv->enc_tf) TwoFishDestroy(priv->enc_tf);
        if (priv->dec_tf) TwoFishDestroy(priv->dec_tf);
        free(priv);
        traceEvent(TRACE_ERROR, "TwoFishInit failed");
        return 1;
    }

    ttt->priv = priv;
    ttt->transform_id = N2N_TRANSFORM_ID_TWOFISH;
    ttt->deinit  = transop_deinit_twofish;
    ttt->addspec = transop_addspec_twofish;
    ttt->tick    = transop_tick_twofish;
    ttt->fwd     = transop_encode_twofish;
    ttt->rev     = transop_decode_twofish;

    return 0;
}

int transop_twofish_init(n2n_trans_op_t *ttt) {
    TwoFish_srand = false;

    if (ttt->priv)
        transop_deinit_twofish(ttt);

    memset(ttt, 0, sizeof(n2n_trans_op_t));

    transop_tf_t *priv = (transop_tf_t *)malloc(sizeof(transop_tf_t));
    if (!priv) {
        traceEvent(TRACE_ERROR, "Failed to allocate priv for twofish");
        return 1;
    }
    priv->enc_tf = NULL;
    priv->dec_tf = NULL;

    ttt->priv = priv;
    ttt->transform_id = N2N_TRANSFORM_ID_TWOFISH;
    ttt->deinit  = transop_deinit_twofish;
    ttt->addspec = transop_addspec_twofish;
    ttt->tick    = transop_tick_twofish;
    ttt->fwd     = transop_encode_twofish;
    ttt->rev     = transop_decode_twofish;

    return 0;
}
