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
 * Fuzz target for the authorization response handlers
 * (oidc_response_authorization_redirect / oidc_response_authorization_post):
 * the browser-facing redirect_uri callback. The OP redirects the browser
 * there, but it is the browser -- anyone -- that delivers the parameters, so
 * state, code, id_token, access_token, token_type, expires_in, error,
 * error_description, session_state, scope and response_mode are all
 * attacker-controlled input to the state-cookie match, the browser-back
 * detection, the response type/mode validation and parameter stripping, the
 * per-flow handlers, the id_token validation, the session save and the final
 * redirect or restore page.
 *
 * Input layout: the first byte selects the scenario the state cookie encodes
 * (bits 0-2: one of the six response types; bit 3: form_post POST rather
 * than GET; bits 4-5: the response_mode recorded in the state, none/query/
 * fragment/form_post; bit 6: prompt=none), the rest is the query string
 * (GET) or form body (POST) as the browser sent it.
 *
 * Two substitutions keep the paths behind the module's own secrets
 * reachable, which random bytes never are:
 *
 *   - the state: every input gets a fresh state cookie (a new nonce, so the
 *     nonce replay cache does not block the success path after the first
 *     hit), and "state=<its browser fingerprint>&" is prepended to the
 *     parameters unless the fuzzer supplied a state of its own -- so the
 *     fuzzer decides between a matching and a mismatching/missing state, but
 *     does not have to guess a SHA-256;
 *   - the id_token: an "id_token=" parameter whose (form-decoded) value
 *     starts with '{' is taken as the token *payload*, which the target
 *     HS256-signs with the provider's client_secret. A present "nonce" claim
 *     is set to the state's nonce, an integer "iat"/"exp" of 0 becomes the
 *     current time, and an "at_hash"/"c_hash" of "@" becomes the correct
 *     hash of the access_token/code parameter, so a seed can reach the
 *     implicit and hybrid success paths while the fuzzer still owns every
 *     other claim and every other parameter.
 *
 * The fixture provider has no jwks_uri (verification uses the static
 * symmetric key only), no token endpoint and no userinfo endpoint: the code
 * flows run up to the token request, which fails at once and offline on the
 * missing URL, with retries disabled so it does not sleep.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"          /* test fixture */
#include "cfg/cfg_int.h"   /* oidc_cfg_t members, for the HTTP retry counts */
#include "cfg/provider.h"  /* oidc_cfg_provider_client_secret_set */
#include "handle/handle.h" /* oidc_response_authorization_redirect / _post */
#include "http.h"          /* oidc_http_url_encode / _decode */
#include "state.h"         /* oidc_state_browser_fingerprint, oidc_state_cookie_name */
#include "mod_auth_openidc.h" /* OIDC_METHOD_GET */
#include "util/util.h"     /* oidc_json_decode_object, oidc_util_key_symmetric_create */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <string.h>

/* the shared secret both the target (signing) and the module (verifying) derive the HS256 key from */
#define FUZZ_CLIENT_SECRET "fuzz-authz-response-shared-secret"

static int g_ready = 0;
static unsigned long g_seq = 0;

static const char *const fuzz_response_types[] = {
    OIDC_PROTO_RESPONSE_TYPE_CODE,	    OIDC_PROTO_RESPONSE_TYPE_IDTOKEN,
    OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN, OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN,
    OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN,    OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN};

static const char *const fuzz_response_modes[] = {
    NULL, OIDC_PROTO_RESPONSE_MODE_QUERY, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, OIDC_PROTO_RESPONSE_MODE_FORM_POST};

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		oidc_cfg_t *cfg = oidc_test_cfg_get();
		/* the fixture provider carries no client_secret; without one the module cannot derive the
		 * symmetric key it verifies HS* id_tokens with, so every token would fail at the signature */
		oidc_cfg_provider_client_secret_set(oidc_test_pool_get(), oidc_cfg_provider_get(cfg),
						    FUZZ_CLIENT_SECRET);
		/* the code flows end in a token request to an endpoint that is not configured: curl fails
		 * at once, offline, on the NULL URL, but the retry back-off would sleep half a second */
		cfg->http_timeout_long.retries = 0;
		cfg->http_timeout_short.retries = 0;
		g_ready = 1;
	}
	return 0;
}

/* the value of the first "name=" parameter in a form-encoded string, form-decoded, or NULL */
static const char *fuzz_param_get(request_rec *r, const char *params, const char *name) {
	apr_table_t *table = apr_table_make(r->pool, 8);
	oidc_util_read_form_encoded_params(r, table, params);
	return apr_table_get(table, name);
}

/* keep a seed's timestamps inside the iat/exp windows: an integer 0 means "now" */
static void fuzz_freshen(oidc_json_t *payload, const char *claim, apr_time_t value) {
	oidc_json_t *v = oidc_json_object_get(payload, claim);
	if ((v != NULL) && oidc_json_is_integer(v) && (oidc_json_integer_value(v) == 0))
		oidc_json_object_set_new(payload, claim, oidc_json_integer((oidc_json_int_t)value));
}

/* a hash claim of "@" becomes the left half of the SHA-256 over the parameter it binds, base64url */
static void fuzz_hash_claim(request_rec *r, oidc_json_t *payload, const char *claim, const char *value) {
	oidc_json_t *v = oidc_json_object_get(payload, claim);
	if ((v == NULL) || !oidc_json_is_string(v) || (strcmp(oidc_json_string_value(v), "@") != 0) || (value == NULL))
		return;
	oidc_jose_error_t err;
	char *hash = NULL;
	unsigned int hash_len = 0;
	char *encoded = NULL;
	if (oidc_jose_hash_string(r->pool, "HS256", value, &hash, &hash_len, &err) == FALSE)
		return;
	if (oidc_util_base64url_encode(r, &encoded, hash, (int)(hash_len / 2), TRUE) <= 0)
		return;
	oidc_json_object_set_new(payload, claim, oidc_json_string(encoded));
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

/*
 * replace an "id_token={...}" parameter by a signed token built from that payload; anything that is
 * not a JSON object payload at a parameter boundary is left exactly as the fuzzer wrote it
 */
static char *fuzz_id_token_substitute(request_rec *r, char *params, const char *nonce) {
	const char *needle = "id_token=";
	const char *pos = params;
	while ((pos = strstr(pos, needle)) != NULL) {
		if ((pos == params) || (pos[-1] == '&'))
			break;
		pos += strlen(needle);
	}
	if (pos == NULL)
		return params;

	const char *start = pos + strlen(needle);
	const char *end = strchr(start, '&');
	char *value = oidc_http_url_decode(r, end ? apr_pstrmemdup(r->pool, start, (apr_size_t)(end - start))
						  : apr_pstrdup(r->pool, start));
	if (value[0] != '{')
		return params;

	oidc_json_t *payload = NULL;
	if ((oidc_json_decode_object(r, value, &payload) == FALSE) || (payload == NULL))
		return params;

	apr_time_t now = apr_time_sec(apr_time_now());
	if (oidc_json_object_get(payload, "nonce") != NULL)
		oidc_json_object_set_new(payload, "nonce", oidc_json_string(nonce));
	fuzz_freshen(payload, "iat", now);
	fuzz_freshen(payload, "exp", now + 600);
	fuzz_hash_claim(r, payload, "at_hash", fuzz_param_get(r, params, "access_token"));
	fuzz_hash_claim(r, payload, "c_hash", fuzz_param_get(r, params, "code"));

	char *token = fuzz_sign(r, payload);
	if (token == NULL)
		return params;

	return apr_pstrcat(r->pool, apr_pstrmemdup(r->pool, params, (apr_size_t)(start - params)),
			   oidc_http_url_encode(r, token), end ? end : "", NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* shallow copy of the fixture request with a per-input pool and its own header and
	 * environment tables, so nothing the handler sets accumulates across inputs */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.user = NULL;
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

	const unsigned int sel = (size > 0) ? data[0] : 0;
	const char *response_type = fuzz_response_types[(sel & 7) % 6];
	const int is_post = (sel & 8) != 0;
	const char *response_mode = fuzz_response_modes[(sel >> 4) & 3];
	const int prompt_none = (sel & 64) != 0;

	/* a state cookie for this scenario, with a nonce no earlier input used */
	const char *nonce = apr_psprintf(pool, "fuzznonce-%lu", ++g_seq);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, nonce);
	oidc_proto_state_set_state(ps, "s1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/index.html");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, response_type);
	if (response_mode != NULL)
		oidc_proto_state_set_response_mode(ps, response_mode);
	oidc_proto_state_set_pkce_state(ps, "pkce-state-1234567890abcdef1234567890abcdef1234567890ab");
	if (prompt_none)
		oidc_proto_state_set_prompt(ps, OIDC_PROTO_PROMPT_NONE);
	oidc_proto_state_set_timestamp_now(ps);
	const char *fingerprint = oidc_state_browser_fingerprint(&r, cfg, nonce);
	const char *cookie = oidc_proto_state_to_cookie(&r, cfg, ps);
	oidc_proto_state_destroy(ps);
	apr_table_set(r.headers_in, "Cookie",
		      apr_psprintf(pool, "foo=bar; %s=%s; baz=zot", oidc_state_cookie_name(&r, fingerprint), cookie));

	char *params = apr_pstrmemdup(pool, (const char *)(size > 0 ? data + 1 : data), size > 0 ? size - 1 : 0);
	if (fuzz_param_get(&r, params, "state") == NULL)
		params = apr_pstrcat(pool, "state=", oidc_http_url_encode(&r, fingerprint), "&", params, NULL);
	params = fuzz_id_token_substitute(&r, params, nonce);

	/* the test stubs serve the POST body out of r->args, which is also the query string */
	r.args = params;
	if (is_post) {
		r.method_number = M_POST;
		r.method = "POST";
		apr_table_set(r.headers_in, "Content-Type", "application/x-www-form-urlencoded");
		r.remaining = (apr_off_t)strlen(r.args);
	} else {
		r.method_number = M_GET;
		r.method = "GET";
	}

	oidc_session_t *session = NULL;
	oidc_session_load(&r, &session);
	if (is_post)
		oidc_response_authorization_post(&r, cfg, session);
	else
		oidc_response_authorization_redirect(&r, cfg, session);
	oidc_session_free(&r, session);

	apr_pool_destroy(pool);
	return 0;
}
