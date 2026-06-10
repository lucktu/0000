/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
*/

#ifdef __linux__

#define _LINUX_IF_H

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#include <net/if.h>     /* if_nametoindex */
#include <net/if_arp.h> /* required for ARPHRD_ETHER */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "n2n.h"

struct rtnl_req {
    struct nlmsghdr nl;
    union {
        struct ifinfomsg ifinfo;
        struct rtmsg     rt;
        struct ifaddrmsg ifaddr;
    };
    uint8_t         buf[256];
};

static void read_mac(const char *ifname, n2n_mac_t mac_addr) {
    int _sock, res;
    struct ifreq ifr;
    macstr_t mac_addr_buf;

    memset(&ifr, 0, sizeof(struct ifreq));

    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ifname, N2N_IFNAMSIZ);

    res = ioctl(_sock, SIOCGIFHWADDR, &ifr);
    if (res < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), res);
    } else
        memcpy(mac_addr, &ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(n2n_mac_t));

    traceEvent(TRACE_DEBUG, "Interface %s has MAC %s",
               ifname,
               macaddr_str(mac_addr_buf, mac_addr));
    close(_sock);
}

static int set_mac(int fd, const char* dev, n2n_mac_t device_mac) {
    int rc;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    memcpy(&ifr.ifr_hwaddr.sa_data, device_mac, sizeof(n2n_mac_t));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    rc = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        return -1;
    }
    return 0;
}

static int netlink_talk(int nl_sock, struct rtnl_req* req) {
    uint8_t buf[1024] = { 0 };

    struct iovec iov = {
        .iov_base = req,
        .iov_len = req->nl.nlmsg_len
    };

    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0
    };

    const struct msghdr msg = {
        .msg_name = &nl_addr,
        .msg_namelen = sizeof(nl_addr),

        .msg_iov = &iov,
        .msg_iovlen = 1,

        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    if (sendmsg(nl_sock, &msg, 0) < 0) {
        traceEvent(TRACE_ERROR, "netlink send() [%s]\n", strerror(errno));
        return -1;
    }

    if (recv(nl_sock, buf, sizeof(buf), 0) > 0) {
        struct nlmsghdr* nlp = (struct nlmsghdr*) buf;
        if (nlp->nlmsg_type == NLMSG_ERROR) {
            return -((struct nlmsgerr*) NLMSG_DATA(nlp))->error;
        } else {
            traceEvent(TRACE_DEBUG, "netlink recv() unexpected msg type: %d\n", nlp->nlmsg_type);
            return 0;
        }
    }
    traceEvent(TRACE_ERROR, "netlink recv() failed [%s]\n", strerror(errno));
    return -1;
}

static int set_device_state(const tuntap_dev* device, bool up) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr = { 0 };
    strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);
    /* retrieve flags */
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        traceEvent(TRACE_INFO, "ioctl(SIOCGIFFLAGS) [%s]\n", strerror(errno));
        close(s);
        return -1;
    }

    /* bring up interface */
    if (up)
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    else
        ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        traceEvent(TRACE_INFO, "ioctl(SIOCSIFFLAGS) [%s]\n", strerror(errno));
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

int set_ipaddress(const tuntap_dev* device, int static_address) {
    int ifnum = if_nametoindex(device->dev_name);
    traceEvent(TRACE_DEBUG, "if_nametoindex(%s) %d\n", device->dev_name, ifnum);

    int error;
    int _sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (_sock < 0) {
        traceEvent(TRACE_ERROR, "socket() [%s][%d]\n", strerror(errno), _sock);
        return -1;
    }

    struct sockaddr_nl nl_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = (uint32_t) getpid(),
        .nl_groups = 0
    };

    if (bind(_sock, (struct sockaddr*) &nl_addr, sizeof(nl_addr)) < 0) {
        fprintf(stderr, "bind() [%s][%d]\n", strerror(errno), _sock);
        close(_sock);
        return -1;
    }

    struct rtnl_req req = { 0 };
    struct rtattr* rta = NULL;

    req.nl.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nl.nlmsg_type  = RTM_SETLINK;
    req.nl.nlmsg_pid   = (uint32_t) getpid();

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_type = ARPHRD_ETHER;
    req.ifinfo.ifi_index = ifnum;
    req.ifinfo.ifi_change = 0xFFFFFFFF;

    rta = (struct rtattr*) (((uint8_t*) &req) + NLMSG_ALIGN(req.nl.nlmsg_len));
    rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    rta->rta_type = IFLA_MTU;
    req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
    memcpy(RTA_DATA(rta), &device->mtu, sizeof(uint32_t));



    if ((error = netlink_talk(_sock, &req)) != 0) {
        traceEvent(TRACE_ERROR, "netlink set_mtu %u: [%s]", device->mtu, strerror(error));
        close(_sock);
        return -1;
    }

    if (static_address) {
        req.nl.nlmsg_len  = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        req.nl.nlmsg_type = RTM_NEWADDR;

        memset(&req.ifaddr, 0, sizeof(req.ifaddr));
        req.ifaddr.ifa_family = AF_INET;
        req.ifaddr.ifa_index = ifnum;
        req.ifaddr.ifa_prefixlen = device->ip_prefixlen;
        req.ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;

        rta = (struct rtattr*) (((uint8_t*) &req) + NLMSG_ALIGN(req.nl.nlmsg_len));
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        rta->rta_type = IFA_LOCAL;
        req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
        memcpy(RTA_DATA(rta), &device->ip_addr, sizeof(struct in_addr));

        rta = (struct rtattr*) (((uint8_t*) &req) + NLMSG_ALIGN(req.nl.nlmsg_len));
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        rta->rta_type = IFA_ADDRESS;
        req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
        memcpy(RTA_DATA(rta), &device->ip_addr, sizeof(struct in_addr));

        if ((error = netlink_talk(_sock, &req)) != 0) {
            traceEvent(TRACE_ERROR, "netlink set_ip: [%s]", strerror(error));
            close(_sock);
            return -1;
        }
    }

    /* set ipv6 address */
    if (static_address && device->ip6_prefixlen > 0) {
        req.nl.nlmsg_len  = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE |NLM_F_ACK;
        req.nl.nlmsg_type = RTM_NEWADDR;

        memset(&req.ifaddr, 0, sizeof(req.ifaddr));
        req.ifaddr.ifa_family = AF_INET6;
        req.ifaddr.ifa_index = ifnum;
        req.ifaddr.ifa_prefixlen = device->ip6_prefixlen;
        req.ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;

        rta = (struct rtattr *)(((uint8_t*) &req) +  NLMSG_ALIGN(req.nl.nlmsg_len));
        rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
        rta->rta_type = IFA_LOCAL;
        req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
        memcpy(RTA_DATA(rta), &device->ip6_addr, sizeof(struct in6_addr));

        if ((error = netlink_talk(_sock, &req)) != 0) {
            traceEvent(TRACE_ERROR, "netlink set_ip6: [%s]", strerror(error));
            close(_sock);
            return -1;
        }
    }

    if (set_device_state(device, true) != 0) {
        traceEvent(TRACE_ERROR, "netlink device up: [%s]", strerror(errno));
        return -1;
    }

    uint32_t address_size = 0;
    if (device->routes) {
        req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        req.nl.nlmsg_type = RTM_NEWROUTE;

        memset(&req.rt, 0, sizeof(req.rt));
        req.rt.rtm_table = RT_TABLE_MAIN;
        req.rt.rtm_protocol = RTPROT_STATIC;
        req.rt.rtm_type = RTN_UNICAST;
        req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
        req.rt.rtm_flags = RTM_F_PREFIX;

        for(int i = 0; i < device->routes_count; i++) {
            route* r = &device->routes[i];
            if (r->family == AF_INET)
                address_size = sizeof(struct in_addr);
            else if (r->family == AF_INET6)
                address_size = sizeof(struct in6_addr);
            else abort();

            req.nl.nlmsg_len  = NLMSG_LENGTH(sizeof(struct rtmsg));
            req.rt.rtm_family = r->family;
            req.rt.rtm_dst_len = r->prefixlen;

            // 1st attribute: DST address
            rta = (struct rtattr *)(((uint8_t*) &req) + NLMSG_ALIGN(req.nl.nlmsg_len));
            rta->rta_type = RTA_DST;
            rta->rta_len = RTA_LENGTH(address_size);
            req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
            memcpy(RTA_DATA(rta), &r->dest, address_size);

            // 2nd attribute: set ifc index and increment the size
            rta = (struct rtattr*)(((uint8_t*) &req) + NLMSG_ALIGN(req.nl.nlmsg_len));
            rta->rta_type = RTA_GATEWAY;
            rta->rta_len =  RTA_LENGTH(address_size);
            req.nl.nlmsg_len = NLMSG_ALIGN(req.nl.nlmsg_len) + rta->rta_len;
            memcpy(RTA_DATA(rta), &r->gateway, address_size);

            if ((error = netlink_talk(_sock, &req)) != 0) {
                char buf1[INET6_ADDRSTRLEN];
                char buf2[INET6_ADDRSTRLEN];
                traceEvent(TRACE_ERROR, "netlink add_route: %s/%u via %s [%s]",
                    inet_ntop(r->family, r->dest, buf1, INET6_ADDRSTRLEN),
                    r->prefixlen,
                    inet_ntop(r->family, r->gateway, buf2, INET6_ADDRSTRLEN),
                    strerror(error)
                );
            }
        }
    }

    close(_sock);
    return 0;
}

static int find_next_n2n_interface(char* if_name, size_t if_name_len) {
    struct if_nameindex *if_ni, *i;
    int max_num = -1;

    if_ni = if_nameindex();
    if (if_ni == NULL) {
        traceEvent(TRACE_ERROR, "if_nameindex() failed: %s", strerror(errno));
        return -1;
    }

    // Find highest numbered n2n interface
    for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
        if (strncmp(i->if_name, "n2n", 3) == 0) {
            int num = atoi(i->if_name + 3);
            if (num > max_num) {
                max_num = num;
            }
        }
    }

    if_freenameindex(if_ni);

    // Set next interface name (n2n0 if no existing interfaces found)
    snprintf(if_name, if_name_len, "n2n%d", max_num + 1);
    return 0;
}

/* ********************************** */

/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver then uses ifconfig
 *  to configure address/mask and MTU.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface,
 *                       if NULL system will assign a name
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param mtu         - MTU for device_ip
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open(tuntap_dev *device, struct tuntap_config* config) {
    char *tuntap_device = "/dev/net/tun";
    struct ifreq ifr;
    int rc;

    if (strcmp(config->if_name, "n2n0") == 0) {
        if (find_next_n2n_interface(config->if_name, N2N_IFNAMSIZ) < 0) {
            traceEvent(TRACE_WARNING, "Failed to scan interfaces, using n2n0");
        }
    }

    device->fd = open(tuntap_device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if(device->fd < 0) {
        printf("ERROR: ioctl() [%s][%d]\n", strerror(errno), errno);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
    strncpy(ifr.ifr_name, config->if_name, IFNAMSIZ);
    rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

    if(rc < 0) {
        traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
        close(device->fd);
        return -1;
    }

    /* set mac address */
    if (!(config->device_mac[0] == 0 && config->device_mac[1] == 0 &&
          config->device_mac[2] == 0 && config->device_mac[3] == 0 &&
          config->device_mac[4] == 0 && config->device_mac[5] == 0))
    {
        set_mac(device->fd, config->if_name, config->device_mac);
    } else {
        /* Derive a stable MAC from the first physical NIC's hardware MAC */
        n2n_mac_t derived_mac = { 0 };
        int s2 = socket(PF_INET, SOCK_DGRAM, 0);
        if (s2 >= 0) {
            struct if_nameindex *ni = if_nameindex();
            if (ni) {
                for (struct if_nameindex *ii = ni; ii->if_index || ii->if_name; ii++) {
                    if (strncmp(ii->if_name, "lo", 3) == 0) continue;
                    if (strncmp(ii->if_name, "n2n", 3) == 0) continue;
                    struct ifreq ifr2 = { 0 };
                    strncpy(ifr2.ifr_name, ii->if_name, IFNAMSIZ);
                    if (ioctl(s2, SIOCGIFHWADDR, &ifr2) < 0) continue;
                    uint8_t *m = (uint8_t*)ifr2.ifr_hwaddr.sa_data;
                    if (m[0]==0 && m[1]==0 && m[2]==0 && m[3]==0 && m[4]==0 && m[5]==0) continue;
                    /* set locally-administered bit, clear multicast bit */
                    derived_mac[0] = (m[0] & 0xFE) | 0x02;
                    memcpy(derived_mac+1, m+1, 5);
                    /* mix in community name so each community gets a distinct MAC */
                    if (config->community_name) {
                        const char *c = config->community_name;
                        for (int k = 0; c[k]; k++)
                            derived_mac[2 + (k % 4)] ^= (uint8_t)c[k];
                    }
                    break;
                }
                if_freenameindex(ni);
            }
            close(s2);
        }
        if (derived_mac[0] || derived_mac[1] || derived_mac[2] ||
            derived_mac[3] || derived_mac[4] || derived_mac[5])
            set_mac(device->fd, config->if_name, derived_mac);
    }

    /* Store the device name for later reuse */
    strncpy(device->dev_name, config->if_name, MIN(IFNAMSIZ, N2N_IFNAMSIZ) );
    memcpy(&device->ip_addr, &config->ip_addr, sizeof(config->ip_addr));
    device->ip_prefixlen = config->ip_prefixlen;
    memcpy(&device->ip6_addr, &config->ip6_addr, sizeof(config->ip6_addr));
    device->ip6_prefixlen = config->ip6_prefixlen;
    device->mtu = config->mtu;
    device->routes_count = config->routes_count;
    device->routes = config->routes;

    read_mac(device->dev_name, device->mac_addr);

    if ( set_ipaddress(device, !config->dyn_ip4) < 0 ) {
        traceEvent(TRACE_ERROR, "Could not setup up interface %s", device->dev_name);
        close(device->fd);
        return -1;
    }

    /* Log interface configuration success (TRACE_INFO - visible with -v) */
    if (device->ip_addr != 0 && !config->dyn_ip4) {
        struct in_addr a;
        a.s_addr = device->ip_addr;
        traceEvent(TRACE_INFO, "Interface %s configured with IP %s/%u",
                   device->dev_name, inet_ntoa(a), device->ip_prefixlen);
    }

    return(device->fd);
}

ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return(read(tuntap->fd, buf, len));
}

ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return(write(tuntap->fd, buf, len));
}

void tuntap_close(struct tuntap_dev *tuntap) {
    close(tuntap->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
    int _sock, res;
    struct ifreq ifr;
    ipstr_t buf;

    memset(&ifr, 0, sizeof(ifr));
    _sock = socket(PF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, tuntap->dev_name, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    res = ioctl(_sock, SIOCGIFADDR, &ifr);
    if (res < 0) {
        perror ("Get ip addr");
    } else
        tuntap->ip_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    close(_sock);

    traceEvent(TRACE_NORMAL, "Interface %s has IPv4 %s",
               tuntap->dev_name,
               inet_ntop(AF_INET, &tuntap->ip_addr, buf, sizeof(buf)));
}

#endif /* #ifdef __linux__ */
