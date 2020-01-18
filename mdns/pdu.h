/*
 * pdu.h
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

#ifndef _MDNS_QUERY
#define _MDNS_QUERY

#include <mdns/types.h>
#include <mdns/header.h>
#include <mdns/question.h>
#include <mdns/record.h>


MDNS_API int mdns_pdu_parse(const void *buffer, size_t data_size,
		mdns_header_callback_fn header_callback_fn,
		mdns_question_callback_fn question_callback_fn,
		mdns_record_callback_fn record_callback_fn);

#endif
