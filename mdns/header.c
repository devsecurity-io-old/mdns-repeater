/*
 * header.c
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


mdns_header_t
mdns_header_parse(const void *buffer, size_t size, size_t *offset)
{
	mdns_header_t hdr = { 0, 0, 0, 0, 0, 0 };

	if (size >= 12)
	{
		uint16_t *data = (uint16_t *)buffer;

		uint16_t transaction_id = ntohs(*data++);
		uint16_t flags          = ntohs(*data++);
		uint16_t questions      = ntohs(*data++);
		uint16_t answer_rrs     = ntohs(*data++);
		uint16_t authority_rrs  = ntohs(*data++);
		uint16_t additional_rrs = ntohs(*data++);

		hdr.transaction_id      = transaction_id;
		hdr.flags               = flags;
		hdr.questions           = questions;
		hdr.answer_rrs          = answer_rrs;
		hdr.authority_rrs       = authority_rrs;
		hdr.additional_rrs      = additional_rrs;

		*offset += 12;
	}

	return hdr;
}

int
mdns_header_write(void *buffer, size_t size, size_t *offset,
		mdns_header_t hdr)
{
	if (*offset + 12 > size)
	{
		return 1;
	}

	uint16_t *data = pointer_offset(buffer, *offset);

	*data++ = htons(hdr.transaction_id);
	*data++ = htons(hdr.flags);
	*data++ = htons(hdr.questions);
	*data++ = htons(hdr.answer_rrs);
	*data++ = htons(hdr.authority_rrs);
	*data++ = htons(hdr.additional_rrs);

	*offset += 12;

	return 0;
}

int
mdns_header_increment_question_counter(void *buffer, size_t size,
		size_t *offset)
{
	if (*offset + 6 > size)
	{
		return 1;
	}

	uint16_t *data = pointer_offset(buffer, *offset);
	data += 2;

	uint16_t questions = ntohs(*data);
	questions++;
	*data = htons(questions);

	return 0;
}

int
mdns_header_increment_answer_rr_counter(void *buffer, size_t size,
		size_t *offset)
{
	if (*offset + 8 > size)
	{
		return 1;
	}

	uint16_t *data = pointer_offset(buffer, *offset);
	data += 3;

	uint16_t answer_rrs = ntohs(*data);
	answer_rrs++;
	*data = htons(answer_rrs);

	return 0;
}

int
mdns_header_increment_authority_rr_counter(void *buffer, size_t size,
		size_t *offset)
{
	if (*offset + 10 > size)
	{
		return 1;
	}

	uint16_t *data = pointer_offset(buffer, *offset);
	data += 4;

	uint16_t authority_rrs = ntohs(*data);
	authority_rrs++;
	*data = htons(authority_rrs);

	return 0;
}

int
mdns_header_increment_additional_rr_counter(void *buffer, size_t size,
		size_t *offset)
{
	if (*offset + 12 > size)
	{
		return 1;
	}

	uint16_t *data = pointer_offset(buffer, *offset);
	data += 5;

	uint16_t additional_rrs = ntohs(*data);
	additional_rrs++;
	*data = htons(additional_rrs);

	return 0;
}
