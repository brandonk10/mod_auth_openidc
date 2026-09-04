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
 * Fuzz target for the back-channel logout endpoint (oidc_logout() with
 * ?logout=backchannel): an unauthenticated POST that anyone on the network
 * can send, not only the OP it is meant for. Everything behind it runs on the
 * caller's bytes -- the form body, the compact JWT parse, a symmetric
 * decryption key sized from the *caller's* "alg" header, provider lookup by
 * "iss", signature verification, iat/aud/azp validation, the "events" claim,
 * the nonce rejection, the jti replay cache and the sid/sub session cleanup.
 *
 * Two input layouts, told apart by the first byte:
 *
 *   - anything else: the bytes are the raw POST body as the caller sent it
 *     (e.g. "logout_token=<compact JWT>"), so the parameter parsing and the
 *     pre-verification JWT handling see arbitrary input;
 *   - a leading '{': the bytes are the *payload* of a logout token, which the
 *     target HS256-signs with the provider's client_secret before POSTing it.
 *     The fuzzer cannot forge an HMAC, so without this the claim validation
 *     behind the signature check would never execute; with it the fuzzer
 *     owns every claim while the token still verifies. An integer "iat" or
 *     "exp" of 0 is replaced by the current time so seeds do not age out of
 *     the iat window.
 *
 * The fixture provider has no jwks_uri, so verification never leaves the
 * process; the token endpoint and userinfo are not involved in this path.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"          /* test fixture */
#include "cfg/cfg_int.h"   /* oidc_cfg_t members, for the HTTP retry counts */
#include "cfg/provider.h"  /* oidc_cfg_provider_client_secret_set */
#include "handle/handle.h" /* oidc_logout */
#include "http.h"          /* oidc_http_url_encode */
#include "util/util.h"     /* oidc_json_decode_object, oidc_util_key_symmetric_create */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <string.h>

/* the shared secret both the target (signing) and the module (verifying) derive the HS256 key from */
#define FUZZ_CLIENT_SECRET "fuzz-backchannel-logout-shared-secret"

static int g_ready = 0;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		/* the fixture provider carries no client_secret; without one the module cannot derive the
		 * symmetric key it verifies HS* logout tokens with, so every token would fail at the
		 * signature and everything behind it would stay dark */
		oidc_cfg_t *cfg = oidc_test_cfg_get();
		oidc_cfg_provider_client_secret_set(oidc_test_pool_get(), oidc_cfg_provider_get(cfg),
						    FUZZ_CLIENT_SECRET);
		/* no provider endpoint is configured, so any path that ends in an outbound HTTP call hands
		 * curl a NULL URL and fails at once, offline -- but the retry back-off would then sleep
		 * half a second per input (the no-kid signature-failure path re-fetches the JWKS without
		 * checking that there is no jwks_uri to fetch from); drop the retries so it fails fast */
		cfg->http_timeout_long.retries = 0;
		cfg->http_timeout_short.retries = 0;
		g_ready = 1;
	}
	return 0;
}

/* keep a seed's timestamps inside the iat window: an integer 0 means "now" */
static void fuzz_freshen(oidc_json_t *payload, const char *claim, apr_time_t value) {
	oidc_json_t *v = oidc_json_object_get(payload, claim);
	if ((v != NULL) && oidc_json_is_integer(v) && (oidc_json_integer_value(v) == 0))
		oidc_json_object_set_new(payload, claim, oidc_json_integer((oidc_json_int_t)value));
}

/*
 * HS256-sign a fuzzer-supplied payload object with the provider secret, the way the OP would;
 * takes ownership of the payload, returns the compact serialization or NULL
 */
static char *fuzz_sign(request_rec *r, oidc_json_t *payload) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *cser = NULL;

	if ((oidc_util_key_symmetric_create(r, FUZZ_CLIENT_SECRET, 0, NULL, TRUE, &jwk) == FALSE) || (jwk == NULL)) {
		oidc_json_decref(payload);
		return NULL;
	}

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, FALSE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	jwt->payload.value.json = payload;
	if (oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err) == TRUE)
		cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);

	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);

	return cser;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow copy of the fixture request with a per-input pool and its own header and
	 * environment tables, so nothing the handler sets accumulates across inputs */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	r.subprocess_env = r.subprocess_env ? apr_table_copy(pool, r.subprocess_env) : apr_table_make(pool, 8);
	/* the ap_pass_brigade stub captures any response body into the request state of the
	 * filter's request: point it at this copy so that lands in the per-input pool too */
	ap_filter_t filter;
	memset(&filter, 0, sizeof(filter));
	filter.r = &r;
	r.output_filters = &filter;

	/* a form POST, the only shape the endpoint reads a logout_token from */
	r.method_number = M_POST;
	r.method = "POST";
	apr_table_set(r.headers_in, "Content-Type", "application/x-www-form-urlencoded");

	char *body = fuzz_strndup(pool, data, size);
	if ((size > 0) && (data[0] == '{')) {
		oidc_json_t *payload = NULL;
		if ((oidc_json_decode_object(&r, body, &payload) == TRUE) && (payload != NULL)) {
			apr_time_t now = apr_time_sec(apr_time_now());
			fuzz_freshen(payload, "iat", now);
			fuzz_freshen(payload, "exp", now + 600);
			char *token = fuzz_sign(&r, payload);
			if (token != NULL)
				body = apr_pstrcat(pool, "logout_token=", oidc_http_url_encode(&r, token), NULL);
		}
	}

	/* the test stubs serve the POST body out of r->args, which doubles as the query string
	 * the dispatcher selects the back-channel handler on */
	r.args = apr_pstrcat(pool, "logout=backchannel&", body, NULL);
	r.remaining = (apr_off_t)strlen(r.args);

	oidc_session_t *session = NULL;
	oidc_session_load(&r, &session);
	oidc_logout(&r, oidc_test_cfg_get(), session);
	oidc_session_free(&r, session);

	apr_pool_destroy(pool);
	return 0;
}
