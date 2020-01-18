/*
 * string.c
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


#define MDNS_INVALID_POS ((size_t)-1)

typedef struct mdns_string_pair
{
	size_t  offset;
	size_t  length;
	bool    ref;
} mdns_string_pair_t;

static bool
is_string_ref(uint8_t val)
{
	return (0xc0 == (val & 0xc0));
}

static mdns_string_pair_t
get_next_substring(const void* rawdata, size_t size, size_t offset)
{
	const uint8_t* buffer = rawdata;
	mdns_string_pair_t pair = { MDNS_INVALID_POS, 0, false };
	if (!buffer[offset])
	{
		pair.offset = offset;
		return pair;
	}

	if (is_string_ref(buffer[offset]))
	{
		if (size < offset + 2)
			return pair;

		offset = (((size_t)(0x3f & buffer[offset]) << 8) |
			  (size_t)buffer[offset + 1]);
		if (offset >= size)
			return pair;

		pair.ref = true;
	}

	size_t length = (size_t)buffer[offset++];
	if (size < offset + length)
		return pair;

	pair.offset = offset;
	pair.length = length;

	return pair;
}

string_t
mdns_string_extract(const void *buffer, size_t size, size_t *offset, char *str,
		size_t capacity)
{
	size_t cur = *offset;
	size_t end = MDNS_INVALID_POS;
	mdns_string_pair_t substr;
	string_t result = { str, 0 };
	char *dst = str;
	size_t remain = capacity;
	do {
		substr = get_next_substring(buffer, size, cur);
		if (substr.offset == MDNS_INVALID_POS)
			return result;
		if (substr.ref && (end == MDNS_INVALID_POS))
			end = cur + 2;
		if (substr.length) {
			size_t to_copy = (substr.length < remain) ?
				substr.length : remain;
			memcpy(dst, pointer_offset_const(buffer, substr.offset),
				to_copy);
			dst += to_copy;
			remain -= to_copy;
			if (remain) {
				*dst++ = '.';
				--remain;
			}
		}
		cur = substr.offset + substr.length;
	}
	while (substr.length);

	if (end == MDNS_INVALID_POS)
		end = cur + 1;
	*offset = end;

	result.length = capacity - remain;
	return result;
}

bool
mdns_string_skip(const void* buffer, size_t size, size_t* offset) {
	size_t cur = *offset;
	mdns_string_pair_t substr;

	do {
		substr = get_next_substring(buffer, size, cur);
		if (substr.offset == MDNS_INVALID_POS)
			return false;
		if (substr.ref) {
			*offset = cur + 2;
			return true;
		}
		cur = substr.offset + substr.length;
	}
	while (substr.length);

	*offset = cur + 1;

	return true;
}

void *
mdns_string_make(void *data, size_t capacity, const char *name, size_t length)
{
	size_t pos = 0;
	size_t last_pos = 0;
	size_t remain = capacity;
	unsigned char *dest = data;
	while ((last_pos < length) &&
		((pos = string_find(name,
				length, '.', last_pos)) != STRING_NPOS))
	{
		size_t sublength = pos - last_pos;
		if (sublength < remain)
		{
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		}
		else
		{
			return dest;
		}
		last_pos = pos + 1;
	}

	if (last_pos < length)
	{
		size_t sublength = length - last_pos;
		if (sublength < capacity)
		{
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		}
		else
		{
			return dest;
		}
	}

	if (remain)
		*dest++ = 0;

	return dest;
}
