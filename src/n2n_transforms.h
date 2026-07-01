/* (c) 2009 Richard Andrews <andrews@ntop.org> */

#ifndef N2N_TRANSFORMS_H_
#define N2N_TRANSFORMS_H_

#include "n2n_keyfile.h"
#include "n2n_wire.h"


#define N2N_TRANSFORM_ID_INVAL          0       /* marks uninitialised data */
#define N2N_TRANSFORM_ID_NULL           1
#define N2N_TRANSFORM_ID_TWOFISH        2
#define N2N_TRANSFORM_ID_AESCBC         3
#define N2N_TRANSFORM_ID_CHACHA20       4
#define N2N_TRANSFORM_ID_SPECK          5
#define N2N_TRANSFORM_ID_USER_START     64
#define N2N_TRANSFORM_ID_MAX            65535

struct n2n_trans_op;
typedef struct n2n_trans_op n2n_trans_op_t;

struct n2n_tostat
{
    uint8_t             can_tx;         /* Does this transop have a valid SA for encoding. */
    n2n_cipherspec_t    tx_spec;        /* If can_tx, the spec used to encode. */
};

typedef struct n2n_tostat n2n_tostat_t;


typedef int             (*n2n_transdeinit_f)( n2n_trans_op_t * arg );
typedef int             (*n2n_transaddspec_f)( n2n_trans_op_t * arg,
                                               const n2n_cipherspec_t * cspec );
typedef n2n_tostat_t    (*n2n_transtick_f)( n2n_trans_op_t * arg,
                                            time_t now );

typedef ssize_t         (*n2n_transform_f)( n2n_trans_op_t * arg,
                                            uint8_t * outbuf,
                                            size_t out_len,
                                            const uint8_t * inbuf,
                                            size_t in_len,
                                            const uint8_t * peer_mac );

/** Holds the info associated with a data transform plugin.
 *
 *  When a packet arrives the transform ID is extracted. This defines the code
 *  to use to decode the packet content. The transform code then decodes the
 *  packet and consults its internal key lookup.
 */
struct n2n_trans_op
{
    void *              priv;   /* opaque data. Key schedule goes here. */

    n2n_transform_t     transform_id;   /* link header enum to a transform */
    size_t              tx_cnt;
    size_t              rx_cnt;

    n2n_transdeinit_f   deinit; /* destructor function */
    n2n_transaddspec_f  addspec; /* parse opaque data from a key schedule file. */
    n2n_transtick_f     tick;   /* periodic maintenance */
    n2n_transform_f     fwd;    /* encode a payload */
    n2n_transform_f     rev;    /* decode a payload */
};

/* Setup a single twofish SA for single-key operation. */
int transop_twofish_setup( n2n_trans_op_t * ttt,
                           n2n_sa_t sa_num,
                           uint8_t * encrypt_pwd,
                           uint64_t encrypt_pwd_len );

/* Initialise an empty transop ready to receive cipherspec elements. */
int  transop_twofish_init( n2n_trans_op_t * ttt );
int  transop_aes_init( n2n_trans_op_t * ttt );
int  edge_init_aes_from_key( n2n_trans_op_t * ttt, const uint8_t * key, size_t key_len );
int  transop_cc20_init( n2n_trans_op_t * ttt );
int  edge_init_cc20_from_key( n2n_trans_op_t * ttt, const uint8_t * key, size_t key_len );
int  transop_speck_init( n2n_trans_op_t * ttt );
int  transop_deinit_speck( n2n_trans_op_t * ttt );
int  setup_speck_key( void * priv, const uint8_t * key, size_t key_len );
int  transop_addspec_speck( n2n_trans_op_t * ttt, const n2n_cipherspec_t * cspec );
n2n_tostat_t transop_tick_speck( n2n_trans_op_t * ttt, time_t now );
ssize_t transop_encode_speck( n2n_trans_op_t * ttt, uint8_t * outbuf, size_t out_len, const uint8_t * inbuf, size_t in_len, const uint8_t * peer_mac );
ssize_t transop_decode_speck( n2n_trans_op_t * ttt, uint8_t * outbuf, size_t out_len, const uint8_t * inbuf, size_t in_len, const uint8_t * peer_mac );
void transop_null_init( n2n_trans_op_t * ttt );

#endif /* N2N_TRANSFORMS_H_ */
