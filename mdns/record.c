/*
 * record.c
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

#include <string.h>
#include <mdns/types.h>
#include <mdns/string.h>
#include <mdns/network.h>
#include <mdns/record.h>


void
mdns_records_parse(const void *buffer, size_t size, size_t *offset,
			mdns_entry_type_t type, size_t records,
			mdns_record_callback_fn callback)
{
	for (size_t i = 0; i < records; ++i)
	{
		char namebuffer[1024];
		string_t name;
		name = mdns_string_extract(buffer, size, offset, namebuffer,
				sizeof(namebuffer));
		const uint16_t *data = pointer_offset_const(buffer, *offset);

		uint16_t rtype  = ntohs(*data++);
		uint16_t rclass = ntohs(*data++);
		bool     cf     = (rclass & 0x8000) >> 15;
		rclass         &= 0x7fff;
		uint32_t ttl    = ntohl(*(const uint32_t *)(const void *)data);
		data += 2;
		uint16_t length = ntohs(*data++);

		*offset += 10;

		callback(type, name, rtype, rclass, cf, ttl, buffer, size,
				*offset, length);

		*offset += length;
	}
}

int
mdns_record_write(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rtype, uint16_t rclass, bool cf, uint32_t ttl)
{
	size_t capacity;
	char *ptr;
	char *new_ptr;
       
	// name
	ptr = pointer_offset(buffer, *offset);
	capacity = size - *offset;
	new_ptr = mdns_string_make(ptr, capacity, name.str, name.length);
	if (new_ptr == NULL)
	{
		return 1;
	}

	*offset = pointer_diff(new_ptr, buffer);
	uint16_t *data = (uint16_t *)new_ptr;

	if (*offset + 8 > size)
	{
		return 1;
	}

	// rtype
	*data++ = htons(rtype);

	// rclass & cache flag
	uint16_t val = (cf ? 0x8000: 0x0000) | (rclass & 0x7fff);
	*data++ = htons(val);

	// ttl
	*((uint32_t *)(void *)data) = htonl(ttl);

	*offset += 8;

	return 0;
}

string_t
mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset,
			size_t length, char *strbuffer, size_t capacity)
{
	//PTR record is just a string
	if ((size >= offset + length) && (length >= 2))
	{
		return mdns_string_extract(buffer, size, &offset, strbuffer,
				capacity);
	}

	return (string_t){ 0, 0 };
}

int
mdns_record_write_ptr(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		string_t ptr)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_PTR, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 2 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*offset += 2;
       
	size_t capacity;
	char *p;
	char *new_ptr;

	p = pointer_offset(buffer, *offset);
	capacity = size - *offset;
	new_ptr = mdns_string_make(p, capacity, ptr.str, ptr.length);
	if (new_ptr == NULL)
	{
		return 1;
	}

	*offset = pointer_diff(new_ptr, buffer);

	// set length
	uint16_t len = pointer_diff(new_ptr, p);
	*len_ptr = htons(len);

	return 0;
}

mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset,
			size_t length, char* strbuffer, size_t capacity)
{
	mdns_record_srv_t srv;

	memset(&srv, 0, sizeof(mdns_record_srv_t));

	// Read the priority, weight, port number and the discovery name
	// SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
	// 2 bytes network-order unsigned priority
	// 2 bytes network-order unsigned weight
	// 2 bytes network-order unsigned port
	// string: discovery (domain) name, minimum 2 bytes when compressed
	if ((size >= offset + length) && (length >= 8)) {
		const uint16_t *recorddata = pointer_offset_const(buffer,
				offset);
		srv.priority = ntohs(*recorddata++);
		srv.weight   = ntohs(*recorddata++);
		srv.port     = ntohs(*recorddata++);
		offset += 6;
		srv.name = mdns_string_extract(buffer, size, &offset, strbuffer,
						capacity);
	}

	return srv;
}

int
mdns_record_write_srv(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl, string_t srvname,
		uint16_t priority, uint16_t weight, uint16_t port)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_SRV, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 8 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*offset += 2;

	uint16_t *data = pointer_offset(buffer, *offset);
	*data++ = htons(priority);
	*data++ = htons(weight);
	*data++ = htons(port);

	*offset += 6;
       
	size_t capacity;
	char *p;
	char *new_ptr;

	p = pointer_offset(buffer, *offset);
	capacity = size - *offset;
	new_ptr = mdns_string_make(p, capacity, srvname.str, srvname.length);
	if (new_ptr == NULL)
	{
		return 1;
	}

	*offset = pointer_diff(new_ptr, buffer);

	// set length
	uint16_t len = pointer_diff(new_ptr, p) + 6;
	*len_ptr = htons(len);

	return 0;
}

network_address_ipv4_t
mdns_record_parse_a(const void *buffer, size_t size, size_t offset,
		size_t length)
{
	network_address_ipv4_t addr;

	network_address_ipv4_initialize(&addr);

	if ((size >= offset + length) && (length == 4)) {
		uint32_t ip = ntohl(*(const uint32_t *)pointer_offset_const(
				buffer, offset));

		network_address_ipv4_set_ip((network_address_t *)&addr, ip);
	}

	return addr;
}

int
mdns_record_write_a(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		network_address_ipv4_t addr)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_A, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 6 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*len_ptr = htons(4);
	*offset += 2;

	uint32_t *ip = pointer_offset(buffer, *offset);
	*ip = htonl(network_address_ipv4_ip((network_address_t *)&addr));
	*offset += 4;

	return 0;
}

network_address_ipv6_t
mdns_record_parse_aaaa(const void *buffer, size_t size, size_t offset,
		size_t length)
{
	network_address_ipv6_t addr;

	network_address_ipv6_initialize(&addr);

	if ((size >= offset + length) && (length == 16)) {
		struct in6_addr ip =
			*(const struct in6_addr *)pointer_offset_const(buffer,
									offset);

		network_address_ipv6_set_ip((network_address_t *)&addr, ip);
	}

	return addr;
}

int
mdns_record_write_aaaa(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		network_address_ipv6_t addr)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_AAAA, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 18 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*len_ptr = htons(16);
	*offset += 2;

	struct in6_addr *ip = pointer_offset(buffer, *offset);
	*ip = network_address_ipv6_ip((network_address_t *)&addr);
	*offset += 16;

	return 0;
}

size_t
mdns_record_parse_txt(const void *buffer, size_t size, size_t offset,
		size_t length, mdns_record_txt_t *records, size_t capacity)
{
	size_t parsed = 0;
	const char *strdata;
	size_t separator, sublength;
	size_t end = offset + length;

	if (size < end)
		end = size;

	while ((offset < end) && (parsed < capacity))
	{
		strdata = pointer_offset_const(buffer, offset);
		sublength = *(const unsigned char *)strdata;

		++strdata;
		offset += sublength + 1;

		separator = 0;
		for (size_t c = 0; c < sublength; ++c) {
			// DNS-SD TXT record keys MUST be
			// printable US-ASCII, [0x20, 0x7E]
			if ((strdata[c] < 0x20) || (strdata[c] > 0x7E))
				break;
			if (strdata[c] == '=') {
				separator = c;
				break;
			}
		}

		if (separator == 0)
			continue;

		if (separator < sublength) {
			records[parsed].key = _string_const(strdata, separator);
			records[parsed].value = 
				_string_const(strdata + separator + 1,
						sublength - (separator + 1));
		}
		else {
			records[parsed].key = _string_const(strdata, sublength);
			records[parsed].value = _string_const(NULL, 0);
		}

		++parsed;
	}

	return parsed;
}

int
mdns_record_write_txt(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		mdns_record_txt_t *txtrecords, size_t rcount)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_TXT, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 2 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	uint16_t len = 0;
	*offset += 2;

	for (size_t itxt = 0; itxt < rcount; ++itxt) {
		uint8_t rlen = 0;

		rlen += txtrecords[itxt].key.length;
		rlen++; // '='
		rlen += txtrecords[itxt].value.length;

		if (*offset + rlen + 1 > size)
		{
			return 1;
		}

		uint8_t *data = pointer_offset(buffer, *offset);
		*data++ = rlen;

		memcpy(data, txtrecords[itxt].key.str,
				txtrecords[itxt].key.length);

		data = pointer_offset(data, txtrecords[itxt].key.length);
		*data++ = '=';

		memcpy(data, txtrecords[itxt].value.str,
				txtrecords[itxt].value.length);

		*offset += (rlen + 1);

		len += rlen + 1;
	}

	// set length
	*len_ptr = htons(len);

	return 0;
}

void
mdns_record_parse_opt(const void *buffer, size_t size, size_t offset,
		size_t length, data_const_t *rdata)
{
	*rdata = _data_const(NULL, 0);

	if (offset + length > size)
	{
		return;
	}

	const char *data = pointer_offset_const(buffer, offset);
	*rdata = _data_const(data, length);

	// TODO: parse OPTION records
}

int
mdns_record_write_opt(void *buffer, size_t size, size_t *offset,
		uint16_t rclass, bool cf, uint32_t ttl,
		data_const_t rdata)
{
	int succ = 1;

	string_t empty_string = _string(NULL, 0);

	succ = mdns_record_write(buffer, size, offset, empty_string,
			MDNS_RECORDTYPE_OPT, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 2 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*offset += 2;
       
	uint16_t len = 0;

	char *data = pointer_offset(buffer, *offset);
	if (*offset + rdata.length > size)
	{
		return 1;
	}

	memcpy(data, rdata.ptr, rdata.length);

	*offset += rdata.length;
	len += rdata.length;

	// set length
	*len_ptr = htons(len);

	return 0;
}

void
mdns_record_parse_nsec(const void *buffer, size_t size, size_t offset,
		size_t length, string_t *next_domain_name, char *strbuffer,
		size_t capacity, data_const_t *type_bitmap_data)
{
	*next_domain_name = _string(NULL, 0);
	*type_bitmap_data = _data_const(NULL, 0);

	if ((offset + length > size) || (length < 2))
	{
		return;
	}

	size_t offset_old = offset;
	*next_domain_name = mdns_string_extract(buffer, size, &offset,
			strbuffer, capacity);

	const char *data = pointer_offset_const(buffer, offset);
	size_t data_len = length - (offset - offset_old);

	*type_bitmap_data = _data_const(data, data_len);
}

int
mdns_record_write_nsec(void *buffer, size_t size, size_t *offset, string_t name,
		uint16_t rclass, bool cf, uint32_t ttl,
		string_t next_domain_name, data_const_t type_bitmap_data)
{
	int succ = 1;

	succ = mdns_record_write(buffer, size, offset, name,
			MDNS_RECORDTYPE_NSEC, rclass, cf, ttl);
	if (succ != 0)
	{
		return succ;
	}

	// record specific part
	if (*offset + 2 > size)
	{
		return 1;
	}

	uint16_t *len_ptr = pointer_offset(buffer, *offset);
	*offset += 2;
       
	size_t capacity;
	char *p;
	char *new_ptr;

	p = pointer_offset(buffer, *offset);
	capacity = size - *offset;
	new_ptr = mdns_string_make(p, capacity, next_domain_name.str,
			next_domain_name.length);
	if (new_ptr == NULL)
	{
		return 1;
	}

	*offset = pointer_diff(new_ptr, buffer);
	uint16_t len = pointer_diff(new_ptr, p);

	if (*offset + type_bitmap_data.length > size)
	{
		return 1;
	}

	memcpy(new_ptr, type_bitmap_data.ptr, type_bitmap_data.length);

	*offset += type_bitmap_data.length;
	len += type_bitmap_data.length;

	// set length
	*len_ptr = htons(len);

	return 0;
}
