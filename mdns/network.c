/*
 * network.c
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

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <mdns/types.h>
#include <mdns/network.h>


string_t
network_address_to_string(char *buffer, size_t capacity,
		const network_address_t *address, bool numeric)
{
	if (address)
	{
		if (address->family == NETWORK_ADDRESSFAMILY_IPV4)
		{
			char host[NI_MAXHOST] = { 0 };
			char service[NI_MAXSERV] = { 0 };
			const network_address_ipv4_t *addr_ipv4 =
				(const network_address_ipv4_t *)address;
			int ret = getnameinfo(
				(const struct sockaddr*)&addr_ipv4->saddr,
				addr_ipv4->address_size, host,
				NI_MAXHOST, service, NI_MAXSERV,
				NI_NUMERICSERV | (numeric ? NI_NUMERICHOST : 0));
			if (ret == 0)
			{
				if (addr_ipv4->saddr.sin_port != 0)
					return string_format(buffer, capacity,
						STRING_CONST("%s:%s"),
						host, service);
				else
					return string_format(buffer, capacity,
						STRING_CONST("%s"), host);
			}
		}
		else if (address->family == NETWORK_ADDRESSFAMILY_IPV6)
		{
			char host[NI_MAXHOST] = { 0 };
			char service[NI_MAXSERV] = { 0 };
			const network_address_ipv6_t* addr_ipv6 =
				(const network_address_ipv6_t*)address;
			int ret = getnameinfo(
				(const struct sockaddr*)&addr_ipv6->saddr,
				addr_ipv6->address_size, host,
				NI_MAXHOST, service, NI_MAXSERV,
				NI_NUMERICSERV | (numeric ? NI_NUMERICHOST : 0));
			if (ret == 0)
			{
				if (addr_ipv6->saddr.sin6_port != 0)
					return string_format(buffer, capacity,
						STRING_CONST("[%s]:%s"), host, service);
				else
					return string_format(buffer, capacity,
						STRING_CONST("%s"), host);
			}
		}
	}
	else {
		return string_copy(buffer, capacity, STRING_CONST("<null>"));
	}

	return string_copy(buffer, capacity, STRING_CONST("<invalid address>"));
}


network_address_t *
network_address_ipv4_initialize(network_address_ipv4_t *address)
{
	memset(address, 0, sizeof(network_address_ipv4_t));

	address->saddr.sin_family = AF_INET;
#if PLATFORM_WINDOWS
	address->saddr.sin_addr.s_addr = INADDR_ANY;
#endif
#if PLATFORM_APPLE
	address->saddr.sin_len = sizeof(address->saddr);
#endif
	address->family = NETWORK_ADDRESSFAMILY_IPV4;
	address->address_size = sizeof(struct sockaddr_in);

	return (network_address_t *)address;
}


network_address_t *
network_address_ipv6_initialize(network_address_ipv6_t *address)
{
	memset(address, 0, sizeof(network_address_ipv6_t));

	address->saddr.sin6_family = AF_INET6;
	address->saddr.sin6_addr = in6addr_any;
#if PLATFORM_APPLE
	address->saddr.sin6_len = sizeof(address->saddr);
#endif
	address->family = NETWORK_ADDRESSFAMILY_IPV6;
	address->address_size = sizeof(struct sockaddr_in6);

	return (network_address_t *)address;
}


void
network_address_ipv4_set_ip(network_address_t *address, uint32_t ip)
{
	if (address && address->family == NETWORK_ADDRESSFAMILY_IPV4)
	{
		((network_address_ipv4_t *)address)->saddr.sin_addr.s_addr = htonl(ip);
	}
}


uint32_t
network_address_ipv4_ip(const network_address_t *address)
{
	if (address && address->family == NETWORK_ADDRESSFAMILY_IPV4)
	{
		const network_address_ipv4_t *address_ipv4 =
			(const network_address_ipv4_t *)address;
		return ntohl(address_ipv4->saddr.sin_addr.s_addr);
	}

	return 0;
}


void
network_address_ipv6_set_ip(network_address_t *address, struct in6_addr ip)
{
	if (address && address->family == NETWORK_ADDRESSFAMILY_IPV6)
	{
		((network_address_ipv6_t *)address)->saddr.sin6_addr = ip;
	}
}


struct in6_addr
network_address_ipv6_ip(const network_address_t *address)
{
	if (address && address->family == NETWORK_ADDRESSFAMILY_IPV6)
	{
		const network_address_ipv6_t *address_ipv6 =
			(const network_address_ipv6_t *)address;
		return address_ipv6->saddr.sin6_addr;
	}

	struct in6_addr noaddr;
	memset(&noaddr, 0, sizeof(noaddr));
	return noaddr;
}

bool
is_ipv6_link_local_address(const network_address_t *address)
{
	if (address && address->family == NETWORK_ADDRESSFAMILY_IPV6)
	{
		const network_address_ipv6_t *address_ipv6 =
			(const network_address_ipv6_t *)address;

		struct in6_addr sin6_addr = address_ipv6->saddr.sin6_addr;

		return IN6_IS_ADDR_LINKLOCAL(&sin6_addr);
	}
	else
	{
		return false;
	}
}
