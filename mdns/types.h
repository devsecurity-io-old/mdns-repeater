/*
 * types.h
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

#ifndef _MDNS_TYPES
#define _MDNS_TYPES

#ifdef __cplusplus
#  define MDNS_EXTERN extern "C"
#  define MDNS_API extern "C"
#else
#  define MDNS_EXTERN extern
#  define MDNS_API extern
#endif


#if !defined(__cplusplus) && !defined(__bool_true_false_are_defined)
typedef enum {
	false = 0,
	true  = 1
} bool;
#endif


#include <inttypes.h>
#include <stddef.h>
#include <netinet/in.h>



/* String tuple holding string data pointer and length. This is used to avoid
 * extra calls to determine string length in each API call */
struct string_t {
	/* String buffer */
	char *str;
	/* Length of string, not including any (optional) zero terminator */
	size_t length;
};

/* Constant string tuple holding unmutable string data pointer and length.
 * see string_t */
struct string_const_t {
	/* String buffer */
	const char *str;
	/* Length of string, not including any (optional) zero terminator */
	size_t length;
};

/* String */
typedef struct string_t          string_t;
/* Constant immutable string */
typedef struct string_const_t    string_const_t;

// String argument helpers
#define STRING_CONST(s) (s), (sizeof((s))-1)
#define STRING_FORMAT(s) (int)(s).length, (s).str

/* Denotes an invalid string position (-1) */
#define STRING_NPOS ((size_t)-1)

string_t string_format(char *buffer, size_t capacity, const char *format,
		size_t length, ...);

string_t string_copy(char *dst, size_t capacity, const char *src,
		size_t length);

size_t string_find(const char* str, size_t length, char c, size_t offset);

static inline string_t
_string(char* str, size_t length)
{
#ifdef __cplusplus
	const string_t s = { str, length };
	return s;
#else	
	return (string_t){ str, length };
#endif
}

static inline string_const_t
_string_const(const char* str, size_t length)
{
#ifdef __cplusplus
	const string_const_t s = { str, length };
	return s;
#else	
	return (string_const_t){ str, length };
#endif
}


struct data_t {
	char *ptr;
	size_t length;
};

struct data_const_t {
	const char *ptr;
	size_t length;
};

typedef struct data_t          data_t;
typedef struct data_const_t    data_const_t;

static inline data_t
_data(char* ptr, size_t length)
{
#ifdef __cplusplus
	const data_t s = { ptr, length };
	return s;
#else	
	return (data_t){ ptr, length };
#endif
}

static inline data_const_t
_data_const(const char* ptr, size_t length)
{
#ifdef __cplusplus
	const data_const_t s = { ptr, length };
	return s;
#else	
	return (data_const_t){ ptr, length };
#endif
}



// Pointer arithmetic
#define pointer_offset(ptr, ofs) (void*)((char*)(ptr) + (ptrdiff_t)(ofs))
#define pointer_offset_const(ptr, ofs) (const void*)((const char*)(ptr) + (ptrdiff_t)(ofs))
#define pointer_diff(first, second) (ptrdiff_t)((const char*)(first) - (const char*)(second))



struct mdns_header_t {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
};

typedef struct mdns_header_t   mdns_header_t;

enum mdns_record_type {
	MDNS_RECORDTYPE_IGNORE = 0,
	MDNS_RECORDTYPE_A      = 1,
	MDNS_RECORDTYPE_PTR    = 12,
	MDNS_RECORDTYPE_TXT    = 16,
	MDNS_RECORDTYPE_AAAA   = 28,
	MDNS_RECORDTYPE_OPT    = 41,
	MDNS_RECORDTYPE_NSEC   = 47,
	MDNS_RECORDTYPE_SRV    = 33
};

typedef enum mdns_record_type  mdns_record_type_t;

enum mdns_entry_type {
	MDNS_ENTRYTYPE_ANSWER = 1,
	MDNS_ENTRYTYPE_AUTHORITY = 2,
	MDNS_ENTRYTYPE_ADDITIONAL = 3,
};

typedef enum mdns_entry_type   mdns_entry_type_t;

enum mdns_class {
	MDNS_CLASS_IN = 1
};

typedef enum mdns_class        mdns_class_t;

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	string_t name;
};

typedef struct mdns_record_srv_t   mdns_record_srv_t;

struct mdns_record_txt_t {
	string_const_t key;
	string_const_t value;
};

typedef struct mdns_record_txt_t   mdns_record_txt_t;

#endif
