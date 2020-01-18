/*
 * record.h
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

#ifndef _MDNS_RECORD
#define _MDNS_RECORD

#include <mdns/types.h>
#include <mdns/network.h>


typedef int (*mdns_record_callback_fn)(mdns_entry_type_t entry, string_t name,
		uint16_t rtype, uint16_t rclass, bool cf,
		uint32_t ttl, const void* data, size_t size,
		size_t offset, size_t length);


MDNS_API void
mdns_records_parse(const void *buffer, size_t size, size_t *offset,
		mdns_entry_type_t type, size_t records,
		mdns_record_callback_fn callback);

MDNS_API int
mdns_record_write(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rtype, uint16_t rclass, bool cf, uint32_t ttl);

MDNS_API string_t
mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset,
		size_t length, char *strbuffer, size_t capacity);

MDNS_API int
mdns_record_write_ptr(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		string_t ptr);

MDNS_API mdns_record_srv_t
mdns_record_parse_srv(const void *buffer, size_t size, size_t offset,
		size_t length, char *strbuffer, size_t capacity);

MDNS_API int
mdns_record_write_srv(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl, string_t srvname,
		uint16_t priority, uint16_t weight, uint16_t port);

MDNS_API network_address_ipv4_t
mdns_record_parse_a(const void *buffer, size_t size, size_t offset, size_t length);

MDNS_API int
mdns_record_write_a(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		network_address_ipv4_t addr);

MDNS_API network_address_ipv6_t
mdns_record_parse_aaaa(const void *buffer, size_t size, size_t offset, size_t length);

MDNS_API int
mdns_record_write_aaaa(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		network_address_ipv6_t addr);

MDNS_API size_t
mdns_record_parse_txt(const void *buffer, size_t size, size_t offset, size_t length,
		mdns_record_txt_t *records, size_t capacity);

MDNS_API int
mdns_record_write_txt(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		mdns_record_txt_t *txtrecords, size_t rcount);

MDNS_API void
mdns_record_parse_opt(const void *buffer, size_t size, size_t offset,
		size_t length, data_const_t *rdata);

MDNS_API int
mdns_record_write_opt(void *buffer, size_t size, size_t *offset,
		uint16_t rclass, bool cf, uint32_t ttl,
		data_const_t rdata);

MDNS_API void
mdns_record_parse_nsec(const void *buffer, size_t size, size_t offset,
		size_t length, string_t *next_domain_name, char *strbuffer,
		size_t capacity, data_const_t *type_bitmap_data);

MDNS_API int
mdns_record_write_nsec(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		string_t next_domain_name, data_const_t type_bitmap_data);

#endif
