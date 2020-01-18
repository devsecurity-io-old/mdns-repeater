/*
 * string.h
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

#ifndef _MDNS_STRING
#define _MDNS_STRING

#include <mdns/types.h>


MDNS_API string_t
mdns_string_extract(const void *buffer, size_t size, size_t *offset, char *str,
		size_t capacity);

MDNS_API bool
mdns_string_skip(const void* buffer, size_t size, size_t* offset);

MDNS_API void *
mdns_string_make(void *data, size_t capacity, const char *name, size_t length);

#endif
