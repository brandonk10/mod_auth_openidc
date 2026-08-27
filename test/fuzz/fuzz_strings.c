/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Copyright (C) 2017-2026 ZmartZone Holding BV - hans.zandbelt@openidc.com
 *
 * Fuzz target for the small hand-rolled string helpers that run over
 * request data before anything has been authenticated: URL encoding and
 * decoding (malformed and truncated %-sequences), HTML and JavaScript
 * escaping of values echoed into pages, HTTP header name normalization,
 * the cookie-domain and hostname-suffix checks, the case-insensitive
 * substring search, issuer and space-separated-list comparisons, the query
 * string splitter, the pre-verification JOSE header peek (which runs on raw
 * tokens from anyone), the state browser fingerprint over the
 * X-Forwarded-For and User-Agent headers, the Accept header check, the
 * https-URL validator applied to values from responses, the constant-time
 * compare, and the log redaction scanners.
 *
 * None of these is more than a byte loop, which is exactly why they are
 * cheap to run in one target: the input is the string, every helper sees
 * all of it, and AddressSanitizer catches the over-read that a boundary
 * mistake in any of them would turn into.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"          /* test fixture */
#include "cfg/parse.h"     /* oidc_cfg_parse_is_valid_url */
#include "http.h"          /* oidc_http_url_encode, ... */
#include "http_int.h"      /* oidc_http_redact_body_for_log / _json_for_log */
#include "proto/proto.h"   /* oidc_proto_jwt_header_peek */
#include "state.h"         /* oidc_state_browser_fingerprint */
#include "util/util.h"     /* oidc_util_html_escape, ... */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

static int g_ready = 0;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		g_ready = 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow copy of the fixture request with a per-input pool and a fresh headers_in */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_make(pool, 4);

	const char *s = fuzz_strndup(pool, data, size);

	/* URL encoding: decode, encode, and the round trip */
	oidc_http_url_encode(&r, oidc_http_url_decode(&r, s));
	oidc_http_url_decode(&r, oidc_http_url_encode(&r, s));

	/* escaping of values echoed into pages, and header-name normalization */
	oidc_util_html_escape(pool, s);
	oidc_util_html_javascript_escape(pool, s);
	oidc_http_hdr_normalize_name(&r, s);

	/* host name checks, both as the host and as the configured domain/suffix */
	oidc_util_cookie_domain_valid("www.example.com", s);
	oidc_util_cookie_domain_valid(s, ".example.com");
	oidc_util_hostname_endswith(s, "example.com");
	oidc_util_hostname_endswith("www.example.com", s);

	/* substring search and comparisons */
	oidc_util_strcasestr(s, "needle");
	oidc_util_strcasestr("a haystack with a Needle in it", s);
	oidc_util_issuer_match(s, "https://idp.example.com");
	oidc_util_issuer_match("https://idp.example.com/", s);
	oidc_util_spaced_string_equals(pool, s, "code id_token");
	oidc_util_spaced_string_contains(pool, s, "openid");
	oidc_util_spaced_string_to_hashtable(pool, s);
	oidc_util_strcmp_const_time(s, "a-fixed-comparison-value");

	/* the query string splitter */
	apr_table_t *params = apr_table_make(pool, 8);
	oidc_util_table_add_query_encoded_params(pool, params, s);

	/* the pre-verification JOSE header peek, kid-only and all-fields */
	char *alg = NULL;
	char *enc = NULL;
	char *kid = NULL;
	oidc_proto_jwt_header_peek(&r, s, NULL, NULL, &kid);
	oidc_proto_jwt_header_peek(&r, s, &alg, &enc, &kid);

	/* the state fingerprint over the forwarded-for and user-agent headers, and the Accept check */
	apr_table_set(r.headers_in, "X-Forwarded-For", s);
	apr_table_set(r.headers_in, "User-Agent", s);
	apr_table_set(r.headers_in, "Accept", s);
	oidc_state_browser_fingerprint(&r, oidc_test_cfg_get(), s);
	oidc_http_hdr_in_accept_contains(&r, "application/json");

	/* the https-URL validator run on values from responses */
	oidc_cfg_parse_is_valid_url(pool, s, "https");
	oidc_cfg_parse_is_valid_http_url(pool, s);

	/* the log redaction scanners */
	oidc_http_param_is_sensitive(s);
	oidc_http_redact_body_for_log(&r, s);
	oidc_http_redact_json_for_log(&r, s);

	apr_pool_destroy(pool);
	return 0;
}
