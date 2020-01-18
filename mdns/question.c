/*
 * question.c
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

#include <mdns/types.h>
#include <mdns/string.h>
#include <mdns/network.h>
#include <mdns/question.h>


void
mdns_question_parse(const void *buffer, size_t size, size_t *offset,
			size_t records, mdns_question_callback_fn callback)
{
	for (size_t i = 0; i < records; ++i)
	{
		char namebuffer[1024];
		string_t name;
		name = mdns_string_extract(buffer, size, offset, namebuffer,
				sizeof(namebuffer));
		const uint16_t *data = pointer_offset_const(buffer, *offset);

		uint16_t qtype  = ntohs(*data++);
		uint16_t qclass = ntohs(*data++);
		bool     qu_q   = (qclass & 0x8000) >> 15;
		qclass         &= 0x7fff;

		*offset += 4;

		callback(name, qtype, qclass, qu_q);
	}
}

int
mdns_question_write(void *buffer, size_t size, size_t *offset, string_t name,
			uint16_t qtype, uint16_t qclass, bool qu_question)
{
	size_t capacity;
	char *ptr;
	char *new_ptr;
       
	ptr = pointer_offset(buffer, *offset);
	capacity = size - *offset;
	new_ptr = mdns_string_make(ptr, capacity, name.str, name.length);
	if (new_ptr == NULL)
	{
		return 1;
	}

	*offset = pointer_diff(new_ptr, buffer);
	uint16_t *data = (uint16_t *)new_ptr;
	
	if (*offset + 4 > size)
	{
		return 1;
	}

	*data++ = htons(qtype);

	uint16_t val = (qu_question ? 0x8000: 0x0000) | (qclass & 0x7fff);
	*data++ = htons(val);

	*offset += 4;

	return 0;
}
