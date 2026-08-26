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
 * Fuzz target for the current-URL derivation (oidc_util_url_cur and the
 * helpers around it): the scheme, host and port the module believes it is
 * serving come from the Host, X-Forwarded-Host, X-Forwarded-Port,
 * X-Forwarded-Proto and RFC 7239 Forwarded request headers -- every one of
 * them set by whoever sends the request -- and the resulting URL feeds the
 * redirect_uri match, the state, the return-to URL and the cookie domain
 * check. The Forwarded parser is hand-rolled (strcasestr plus in-place
 * terminators), and the host parser has an IPv6 bracket branch.
 *
 * Input layout: the first line is the request-target (r->uri, with anything
 * after '?' as r->args; a non-'/' target takes the forward-proxy branch that
 * runs apr_uri_parse), every following "Name: value" line becomes a request
 * header. The derivation runs once per OIDCXForwardedHeaders combination,
 * so each header parser sees the input whether or not it is trusted.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"          /* test fixture */
#include "util/util.h"     /* oidc_util_url_cur_matches */
#include "util/util_cfg.h" /* oidc_util_url_cur, oidc_util_url_cur_host, oidc_util_url_abs */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <string.h>

static int g_ready = 0;

static const oidc_hdr_x_forwarded_t fuzz_modes[] = {
    OIDC_HDR_NONE,
    OIDC_HDR_X_FORWARDED_HOST,
    OIDC_HDR_X_FORWARDED_PORT,
    OIDC_HDR_X_FORWARDED_PROTO,
    OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO,
    OIDC_HDR_FORWARDED,
    OIDC_HDR_FORWARDED | OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO,
};

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

	/* shallow copy of the fixture request with a per-input pool and a fresh headers_in: the
	 * Forwarded parser writes terminators into the header value it reads, so the fuzzed
	 * headers must never live in the shared fixture table */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_make(pool, 8);

	char *input = apr_pstrmemdup(pool, (const char *)data, size);
	char *last = NULL;
	char *line = apr_strtok(input, "\n", &last);

	/* first line: the request-target */
	r.uri = apr_pstrdup(pool, line ? line : "");
	r.unparsed_uri = r.uri;
	r.args = NULL;
	char *q = strchr(r.uri, '?');
	if (q != NULL) {
		r.args = q + 1;
		r.uri = apr_pstrmemdup(pool, r.uri, (apr_size_t)(q - r.uri));
	}

	/* remaining lines: request headers (an empty input has no first line to continue from) */
	while ((line != NULL) && ((line = apr_strtok(NULL, "\n", &last)) != NULL)) {
		char *colon = strchr(line, ':');
		if (colon == NULL)
			continue;
		*colon = '\0';
		char *value = colon + 1;
		while ((*value == ' ') || (*value == '\t'))
			value++;
		apr_table_add(r.headers_in, line, value);
	}

	oidc_cfg_t *cfg = oidc_test_cfg_get();
	for (size_t i = 0; i < sizeof(fuzz_modes) / sizeof(fuzz_modes[0]); i++) {
		oidc_util_url_cur(&r, fuzz_modes[i]);
		oidc_util_url_cur_host(&r, fuzz_modes[i]);
	}
	oidc_util_url_cur_is_secure(&r, cfg);
	oidc_util_url_matches_redirect_uri(&r, cfg);
	oidc_util_url_cur_matches(&r, "https://www.example.com/protected/");
	oidc_util_url_abs(&r, cfg, "/relative/path");
	oidc_util_url_abs(&r, cfg, r.unparsed_uri);

	apr_pool_destroy(pool);
	return 0;
}
