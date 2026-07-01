/* upnp.h - Local NAT-PMP/PCP and UPnP IGD port mapping for n2n
 *
 * Protocol priority: PCP > NAT-PMP > UPnP IGD2 > UPnP IGD1
 * No external library dependencies.
 * Supports Linux, macOS/BSD, Windows.
 */

#ifndef _N2N_UPNP_H_
#define _N2N_UPNP_H_

#include <stdint.h>

/* Result codes */
#define UPNP_OK              0
#define UPNP_ERR_SOCKET     -1
#define UPNP_ERR_TIMEOUT    -2
#define UPNP_ERR_RESPONSE   -3
#define UPNP_ERR_NOTFOUND   -4

/* Port mapping lease time in seconds */
#define UPNP_LEASE_TIME      3600

/* Renew when this many seconds remain before expiry (80% of lease) */
#define UPNP_RENEW_THRESHOLD (UPNP_LEASE_TIME * 4 / 5)

/**
 * Try NAT-PMP first, then UPnP IGD as fallback.
 * Maps external_port -> internal_port (UDP) on the gateway.
 * Pass external_port=0 to use internal_port as external port too.
 * On success, *mapped_port is set to the actual external port assigned.
 * Returns UPNP_OK on success, negative error code on failure.
 */
int upnp_map_port(uint16_t internal_port, uint16_t external_port,
                  uint16_t *mapped_port);

/**
 * Renew an existing port mapping before its lease expires.
 * Call periodically (every UPNP_RENEW_THRESHOLD seconds).
 * Returns UPNP_OK on success.
 */
int upnp_renew_port(uint16_t internal_port, uint16_t external_port);

/**
 * Delete a previously created port mapping.
 * Called automatically on clean shutdown via edge_deinit().
 */
void upnp_unmap_port(uint16_t external_port);

#endif /* _N2N_UPNP_H_ */
