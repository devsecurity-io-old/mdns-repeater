/*
 * callbacks.c
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

#include <stdio.h>
#include <mdns/types.h>
#include <mdns/logging.h>
#include <mdns/network.h>
#include <mdns/record.h>


int
print_header_callback_fn(mdns_header_t hdr)
{
	log_message(LOG_DEBUG, "transaction_id: 0x%04X", hdr.transaction_id);
	log_message(LOG_DEBUG, "flags:          0x%04X", hdr.flags);
	log_message(LOG_DEBUG, "questions:      %u",     hdr.questions);
	log_message(LOG_DEBUG, "answer_rrs:     %u",     hdr.answer_rrs);
	log_message(LOG_DEBUG, "authority_rrs:  %u",     hdr.authority_rrs);
	log_message(LOG_DEBUG, "additional_rrs: %u",     hdr.additional_rrs);

	return 0;
}


int
print_question_callback_fn(string_t name, uint16_t qtype, uint16_t qclass,
		bool qu_question)
{
	if (qtype == MDNS_RECORDTYPE_PTR) {
		log_message(LOG_DEBUG, "query %.*s PTR qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else if (qtype == MDNS_RECORDTYPE_SRV) {
		log_message(LOG_DEBUG, "query %.*s SRV qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else if (qtype == MDNS_RECORDTYPE_A) {
		log_message(LOG_DEBUG, "query %.*s A qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else if (qtype == MDNS_RECORDTYPE_AAAA) {
		log_message(LOG_DEBUG, "query %.*s AAAA qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else if (qtype == MDNS_RECORDTYPE_TXT) {
		log_message(LOG_DEBUG, "query %.*s TXT qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else if (qtype == MDNS_RECORDTYPE_NSEC) {
		log_message(LOG_DEBUG, "query %.*s NSEC qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qclass, qu_question);
	}
	else {
		log_message(LOG_DEBUG,
			"query %.*s qtype 0x%x qclass 0x%x qu 0x%x",
			STRING_FORMAT(name), qtype, qclass, qu_question);
	}

	return 0;
}


int
print_record_callback_fn(mdns_entry_type_t entry, string_t name, uint16_t rtype,
		uint16_t rclass, bool cf, uint32_t ttl, const void *data,
		size_t size, size_t offset, size_t length)
{
	char namebuffer[1024];
	const char* entrytype =
		(entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
		((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" :
		((entry == MDNS_ENTRYTYPE_ADDITIONAL) ? "additional": "?"));

	if (rtype == MDNS_RECORDTYPE_PTR) {
		string_t namestr;

		namestr = mdns_record_parse_ptr(data, size, offset, length,
				namebuffer, sizeof(namebuffer));

		log_message(LOG_DEBUG,
			"%s %.*s PTR %.*s rclass 0x%x flush 0x%x ttl %u "
			"length %lu",
			entrytype, STRING_FORMAT(name), STRING_FORMAT(namestr),
			rclass, cf, ttl, length);
	}
	else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv;

		srv = mdns_record_parse_srv(data, size, offset, length,
				namebuffer, sizeof(namebuffer));

		log_message(LOG_DEBUG,
			"%s %.*s SRV %.*s priority %d weight %d port %d "
			"rclass 0x%x flush 0x%x ttl %u length %lu",
			entrytype, STRING_FORMAT(name), STRING_FORMAT(srv.name),
			srv.priority, srv.weight, srv.port,
			rclass, cf, ttl, length);
	}
	else if (rtype == MDNS_RECORDTYPE_A) {
		network_address_ipv4_t addr;
		string_t addrstr;

		addr = mdns_record_parse_a(data, size, offset, length);

		addrstr = network_address_to_string(namebuffer,
				sizeof(namebuffer), (network_address_t *)&addr,
				true);

		log_message(LOG_DEBUG,
			"%s %.*s A %.*s rclass 0x%x flush 0x%x "
			"ttl %u length %lu",
			entrytype, STRING_FORMAT(name), STRING_FORMAT(addrstr),
			rclass, cf, ttl, length);
	}
	else if (rtype == MDNS_RECORDTYPE_AAAA) {
		network_address_ipv6_t addr;
		string_t addrstr;

		addr = mdns_record_parse_aaaa(data, size, offset, length);

		addrstr = network_address_to_string(namebuffer,
				sizeof(namebuffer), (network_address_t *)&addr,
				true);

		log_message(LOG_DEBUG,
			"%s %.*s AAAA %.*s rclass 0x%x flush 0x%x ttl %u "
			"length %lu",
			entrytype, STRING_FORMAT(name), STRING_FORMAT(addrstr),
			rclass, cf, ttl, length);
	}
	else if (rtype == MDNS_RECORDTYPE_TXT) {
		mdns_record_txt_t *txtrecord;
		size_t parsed;

		txtrecord = (void *)namebuffer;
		parsed = mdns_record_parse_txt(data, size,
				offset, length, txtrecord,
				sizeof(namebuffer) / sizeof(mdns_record_txt_t));

		log_message(LOG_DEBUG, "%s %.*s TXT rclass 0x%x flush 0x%x "
			"ttl %u length %lu",
			entrytype, STRING_FORMAT(name),
			rclass, cf, ttl, length);

		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtrecord[itxt].value.length) {
				log_message(LOG_DEBUG, "- %.*s = %.*s",
					STRING_FORMAT(txtrecord[itxt].key),
					STRING_FORMAT(txtrecord[itxt].value));
			}
			else {
				log_message(LOG_DEBUG, "- %.*s =",
					STRING_FORMAT(txtrecord[itxt].key));
			}
		}
	}
	else if (rtype == MDNS_RECORDTYPE_OPT) {
		data_const_t rdata;

		mdns_record_parse_opt(data, size, offset, length,
			&rdata);

		log_message(LOG_DEBUG,
			"%s OPT max_udp_payload_accepted 0x%x flush 0x%x "
			"ext_rcode_and_flags 0x%x length %lu",
			entrytype,
			rclass, cf, ttl, length);
	}
	else if (rtype == MDNS_RECORDTYPE_NSEC) {
		string_t next_domain_name;
		data_const_t type_bitmap_data;

		mdns_record_parse_nsec(data, size, offset, length,
			&next_domain_name, namebuffer, sizeof(namebuffer),
			&type_bitmap_data);

		log_message(LOG_DEBUG,
			"%s %.*s NSEC %.*s rclass 0x%x flush 0x%x ttl %u "
			"length %lu",
			entrytype, STRING_FORMAT(name),
			STRING_FORMAT(next_domain_name),
			rclass, cf, ttl, length);
	}
	else {
		log_message(LOG_DEBUG,
			"%s %.*s rtype 0x%x rclass 0x%x flush 0x%x ttl %u "
			"length %lu",
			entrytype, STRING_FORMAT(name),
			rtype, rclass, cf, ttl, length);
	}

	return 0;
}
