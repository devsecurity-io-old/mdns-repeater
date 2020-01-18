/*
 * types.c
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <mdns/types.h>


string_t
string_format(char *buffer, size_t capacity, const char *format,
		size_t length, ...)
{
	va_list list;
	int n;

	if (!capacity)
		return (string_t){buffer, 0};

	if (!length)
	{
		buffer[0] = 0;
		return (string_t){buffer, 0};
	}

	va_start(list, length);
	n = vsnprintf(buffer, capacity, format, list);
	va_end(list);

	if ((n > -1) && ((unsigned int)n < capacity))
	{
		return (string_t) {buffer, (unsigned int)n};
	}

	return (string_t){buffer, capacity - 1};
}

string_t
string_copy(char *dst, size_t capacity, const char *src, size_t length)
{
	if (capacity)
	{
		if (length)
		{
			if (length >= capacity)
				length = capacity - 1;
			if (dst != src)
				memcpy(dst, src, length);
		}

		dst[length] = 0;

		return (string_t) {dst, length};
	}

	return (string_t) {dst, 0};
}

size_t
string_find(const char* str, size_t length, char c, size_t offset)
{
	const void* found;

	if (offset >= length)
		return STRING_NPOS;

	found = memchr(str + offset, c, length - offset);
	if (found)
		return (size_t)pointer_diff(found, str);

	return STRING_NPOS;
}
