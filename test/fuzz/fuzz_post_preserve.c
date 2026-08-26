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
 * Fuzz target for oidc_response_post_preserve_javascript(): with
 * OIDCPreservePost On, the parameters of a browser's form POST to a
 * protected URL are rendered into a JavaScript object literal inside an
 * inline <script> (and the redirect location into a window.location
 * assignment), to be stored in the browser's sessionStorage across the
 * authentication round trip. Every name and value in that script comes
 * straight from the POST body, i.e. from whoever submits the form; the
 * URL-encoding of the pairs and the JavaScript escaping of the location are
 * what stand between that and script injection into the module's own page.
 *
 * Input layout: the first line is the redirect location (empty for none),
 * the rest is the form-encoded POST body as the browser sent it.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"             /* test fixture */
#include "cfg/dir.h"          /* oidc_cmd_dir_preserve_post_set */
#include "cfg/directives.h"   /* OIDCPreservePost */
#include "handle/handle.h"    /* oidc_response_post_preserve_javascript */
#include "mod_auth_openidc.h" /* auth_openidc_module */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <string.h>

static int g_ready = 0;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		/* OIDCPreservePost On for the fixture's location: off, the function returns before it
		 * reads a single byte of the body */
		request_rec *r = oidc_test_request_get();
		oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
		oidc_cmd_dir_preserve_post_set(oidc_test_cmd_get(OIDCPreservePost), dir_cfg, "On");
		g_ready = 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow copy of the fixture request with a per-input pool and its own headers_in */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_copy(pool, r.headers_in);

	char *input = apr_pstrmemdup(pool, (const char *)data, size);
	char *body = "";
	char *nl = strchr(input, '\n');
	if (nl != NULL) {
		*nl = '\0';
		body = nl + 1;
	}
	const char *location = (input[0] != '\0') ? input : NULL;

	/* a form POST, the only shape the function preserves; the test stubs serve the body
	 * out of r->args */
	r.method_number = M_POST;
	r.method = "POST";
	apr_table_set(r.headers_in, "Content-Type", "application/x-www-form-urlencoded");
	r.args = body;
	r.remaining = (apr_off_t)strlen(body);

	char *javascript = NULL;
	char *javascript_method = NULL;
	oidc_response_post_preserve_javascript(&r, location, &javascript, &javascript_method);

	apr_pool_destroy(pool);
	return 0;
}
