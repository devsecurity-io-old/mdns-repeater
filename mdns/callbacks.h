/*
 * callbacks.h
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

#ifndef _MDNS_CALLBACKS
#define _MDNS_CALLBACKS

#include <mdns/types.h>


MDNS_API int
print_header_callback_fn(mdns_header_t hdr);

MDNS_API int
print_question_callback_fn(string_t name, uint16_t qtype, uint16_t qclass,
		bool qu_question);

MDNS_API int
print_record_callback_fn(mdns_entry_type_t entry, string_t name, uint16_t rtype,
		uint16_t rclass, bool cf, uint32_t ttl, const void *data,
		size_t size, size_t offset, size_t length);

#endif
