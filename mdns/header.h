/*
 * header.h
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

#ifndef _MDNS_HEADER
#define _MDNS_HEADER

#include <mdns/types.h>


typedef int (*mdns_header_callback_fn)(mdns_header_t hdr);


MDNS_API mdns_header_t
mdns_header_parse(const void *buffer, size_t size, size_t *offset);

MDNS_API int
mdns_header_write(void *buffer, size_t size, size_t *offset, mdns_header_t hdr);

MDNS_API int
mdns_header_increment_question_counter(void *buffer, size_t size,
		size_t *offset);

MDNS_API int
mdns_header_increment_answer_rr_counter(void *buffer, size_t size,
		size_t *offset);

MDNS_API int
mdns_header_increment_authority_rr_counter(void *buffer, size_t size,
		size_t *offset);

MDNS_API int
mdns_header_increment_additional_rr_counter(void *buffer, size_t size,
		size_t *offset);

#endif
