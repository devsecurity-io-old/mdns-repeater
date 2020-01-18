/*
 * pdu.c
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

#include <mdns/header.h>
#include <mdns/question.h>
#include <mdns/record.h>


int mdns_pdu_parse(const void *buffer, size_t data_size,
		mdns_header_callback_fn header_callback_fn,
		mdns_question_callback_fn question_callback_fn,
		mdns_record_callback_fn record_callback_fn)
{
	size_t offset = 0;
	mdns_header_t hdr;


	// parse header
	hdr = mdns_header_parse(buffer, data_size, &offset);
	header_callback_fn(hdr);

	// parse question records
	mdns_question_parse(buffer, data_size, &offset, hdr.questions,
			question_callback_fn);

	// parse answer records
	mdns_records_parse(buffer, data_size, &offset,
			MDNS_ENTRYTYPE_ANSWER, hdr.answer_rrs,
			record_callback_fn);

	mdns_records_parse(buffer, data_size, &offset,
			MDNS_ENTRYTYPE_AUTHORITY, hdr.authority_rrs,
			record_callback_fn);

	mdns_records_parse(buffer, data_size, &offset,
			MDNS_ENTRYTYPE_ADDITIONAL, hdr.additional_rrs,
			record_callback_fn);

	return 0;
}
