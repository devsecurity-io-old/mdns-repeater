/*
 * network.h
 * Copyright (C) 2020 Matthias Dettling
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _MDNS_NETWORK
#define _MDNS_NETWORK

#include <mdns/types.h>


/*
Maximum length of a numeric network address string, including zero
terminator
*/
#define NETWORK_ADDRESS_NUMERIC_MAX_LENGTH 46


typedef socklen_t network_address_size_t;

typedef enum {
	NETWORK_ADDRESSFAMILY_IPV4     = 0,
	NETWORK_ADDRESSFAMILY_IPV6
} network_address_family_t;

#define NETWORK_DECLARE_NETWORK_ADDRESS    \
	network_address_family_t family;       \
	network_address_size_t   address_size

typedef struct network_address_t {
	NETWORK_DECLARE_NETWORK_ADDRESS;
} network_address_t;

#define NETWORK_DECLARE_NETWORK_ADDRESS_IP   \
	NETWORK_DECLARE_NETWORK_ADDRESS

/*
From man page ip.7:
- port is in network byte order
- s_addr is in network byte order

struct sockaddr_in {
    sa_family_t    sin_family; // address family: AF_INET
    in_port_t      sin_port;   // port in network byte order
    struct in_addr sin_addr;   // internet address
};

struct in_addr {
    uint32_t       s_addr;     // address in network byte order
};
*/

typedef struct network_address_ipv4_t {
	NETWORK_DECLARE_NETWORK_ADDRESS_IP;
	struct sockaddr_in     saddr;
} network_address_ipv4_t;

typedef struct network_address_ipv6_t {
	NETWORK_DECLARE_NETWORK_ADDRESS_IP;
	struct sockaddr_in6    saddr;
} network_address_ipv6_t;


MDNS_API string_t
network_address_to_string(char *buffer, size_t capacity,
		const network_address_t *address, bool numeric);

MDNS_API network_address_t *
network_address_ipv4_initialize(network_address_ipv4_t *address);

MDNS_API network_address_t *
network_address_ipv6_initialize(network_address_ipv6_t *address);

MDNS_API void
network_address_ipv4_set_ip(network_address_t *address, uint32_t ip);

MDNS_API uint32_t
network_address_ipv4_ip(const network_address_t *address);

MDNS_API void
network_address_ipv6_set_ip(network_address_t *address, struct in6_addr ip);

MDNS_API struct in6_addr
network_address_ipv6_ip(const network_address_t *address);

MDNS_API bool
is_ipv6_link_local_address(const network_address_t *address);

#endif
