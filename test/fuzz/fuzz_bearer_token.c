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
 * Fuzz target for the OAuth 2.0 resource-server entry point: bearer token
 * extraction (oidc_oauth_get_bearer_token: the Authorization header in the
 * Bearer and Basic schemes, the query string and POST body with their
 * duplicate-parameter rejection, and a cookie) followed by the whole
 * unauthenticated request path behind it (oidc_oauth_check_userid: local JWT
 * access-token parse/decrypt/verify against the static shared key,
 * exp/iss/aud validation, the validation cache, REMOTE_USER derivation, the
 * header scrub, claim propagation and the WWW-Authenticate error response).
 * Every byte of it is chosen by the API client -- anyone.
 *
 * Input layout: the first byte selects the per-location
 * OIDCOAuthAcceptTokenAs set (bits 0-4: header, post, query, cookie, basic;
 * none set means the default, header) and the request method (bit 5: POST,
 * bit 6: OPTIONS, i.e. the CORS-preflight pass-through); the rest holds
 * up to three newline-separated sections: the Authorization header value,
 * the query string (which the test stubs also serve as the POST body) and
 * the Cookie header value.
 *
 * A Bearer value or an access_token parameter that starts with '{' is
 * taken as a JWT *payload* and HS256-signed with the configured shared key,
 * with an integer "exp"/"iat" of 0 replaced by the current time: the fuzzer
 * cannot forge an HMAC, and without this the claim validation and the
 * request-user/claim propagation behind the signature check would never
 * run. The fixture has no OIDCOAuthVerifyJwksUri and no introspection
 * endpoint, so nothing here goes near the network.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"             /* test fixture */
#include "cfg/cfg_int.h"      /* oidc_cfg_t members, for the HTTP retry counts */
#include "cfg/dir.h"          /* oidc_cfg_dir_config_create, oidc_cmd_dir_accept_oauth_token_in_set */
#include "cfg/directives.h"   /* OIDCOAuthAcceptTokenAs, ... */
#include "cfg/oauth.h"        /* oidc_cmd_oauth_verify_shared_keys_set, ... */
#include "cfg/provider.h"     /* oidc_cfg_provider_client_secret_set */
#include "http.h"             /* oidc_http_url_encode / _decode */
#include "mod_auth_openidc.h" /* auth_openidc_module */
#include "oauth.h"            /* oidc_oauth_get_bearer_token, oidc_oauth_check_userid */
#include "util/util.h"        /* oidc_json_decode_object, oidc_util_key_symmetric_create */
/* clang-format on */

#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <string.h>

/* the shared key both the target (signing) and OIDCOAuthVerifySharedKeys (verifying) use */
#define FUZZ_SHARED_SECRET "fuzz-bearer-token-shared-secret-0123456789"
#define FUZZ_ISSUER "https://as.example.com"
#define FUZZ_AUDIENCE "fuzz-resource"

static int g_ready = 0;

/*
 * The OIDCOAuthVerifySharedKeys key lives in the config for the life of the process, referenced
 * only from APR pool memory, which LeakSanitizer does not scan -- so at exit it would be reported
 * as a leak and the run would fail. Keeping the heap handle in a global (a root LSan does scan)
 * makes it reachable; an atexit handler releases it so the end-of-run check stays clean as well.
 * The same pattern as fuzz_jwt's key set.
 */
#define FUZZ_MAX_SHARED_KEYS 4
static void *g_cjose_keys[FUZZ_MAX_SHARED_KEYS];
static apr_hash_t *g_shared_keys = NULL;

static void fuzz_shared_keys_destroy(void) {
	if (g_shared_keys != NULL)
		oidc_jwk_list_destroy_hash(g_shared_keys);
	g_shared_keys = NULL;
	for (int i = 0; i < FUZZ_MAX_SHARED_KEYS; i++)
		g_cjose_keys[i] = NULL;
}

static const char *const fuzz_accept_in[] = {"header", "post", "query", "cookie", "basic"};

/* a cmd_parms on the given pool, the way the fixture's oidc_test_cmd_get builds one */
static cmd_parms *fuzz_cmd(apr_pool_t *pool, request_rec *r, const char *directive) {
	cmd_parms *cmd = apr_pcalloc(pool, sizeof(cmd_parms));
	cmd->server = r->server;
	cmd->pool = pool;
	cmd->temp_pool = pool;
	cmd->directive = apr_pcalloc(pool, sizeof(ap_directive_t));
	cmd->directive->directive = directive;
	return cmd;
}

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		apr_pool_t *pool = oidc_test_pool_get();
		request_rec *r = oidc_test_request_get();
		oidc_cfg_t *cfg = oidc_test_cfg_get();
		/* the static key the JWT access-token verification runs against, plus a client_secret
		 * the decryption-key candidate is derived from, and an issuer and audience so the
		 * post-signature claim checks have something to enforce */
		oidc_cmd_oauth_verify_shared_keys_set(fuzz_cmd(pool, r, OIDCOAuthVerifySharedKeys), NULL,
						      FUZZ_SHARED_SECRET);
		g_shared_keys = oidc_cfg_oauth_verify_shared_keys_get(cfg);
		if (g_shared_keys != NULL) {
			int i = 0;
			for (apr_hash_index_t *hi = apr_hash_first(pool, g_shared_keys);
			     (hi != NULL) && (i < FUZZ_MAX_SHARED_KEYS); hi = apr_hash_next(hi)) {
				oidc_jwk_t *jwk = NULL;
				apr_hash_this(hi, NULL, NULL, (void **)&jwk);
				g_cjose_keys[i++] = jwk->cjose_jwk;
			}
			atexit(fuzz_shared_keys_destroy);
		}
		oidc_cmd_oauth_verify_issuer_set(fuzz_cmd(pool, r, OIDCOAuthVerifyIssuer), NULL, FUZZ_ISSUER);
		oidc_cmd_oauth_verify_aud_values_set(fuzz_cmd(pool, r, OIDCOAuthVerifyAudience), NULL, FUZZ_AUDIENCE);
		oidc_cfg_provider_client_secret_set(pool, oidc_cfg_provider_get(cfg), FUZZ_SHARED_SECRET);
		/* no endpoint is configured, so a path that ends in an outbound HTTP call hands curl a
		 * NULL URL and fails at once, offline; drop the retries so it does not sleep either */
		cfg->http_timeout_long.retries = 0;
		cfg->http_timeout_short.retries = 0;
		g_ready = 1;
	}
	return 0;
}

/* keep a seed's timestamps inside the exp/iat windows: an integer 0 means "now" */
static void fuzz_freshen(oidc_json_t *payload, const char *claim, apr_time_t value) {
	oidc_json_t *v = oidc_json_object_get(payload, claim);
	if ((v != NULL) && oidc_json_is_integer(v) && (oidc_json_integer_value(v) == 0))
		oidc_json_object_set_new(payload, claim, oidc_json_integer((oidc_json_int_t)value));
}

/* a '{'-prefixed value becomes an HS256-signed token over that payload; anything else is returned as-is */
static const char *fuzz_maybe_sign(request_rec *r, const char *value) {
	if ((value == NULL) || (value[0] != '{'))
		return value;

	oidc_json_t *payload = NULL;
	if ((oidc_json_decode_object(r, value, &payload) == FALSE) || (payload == NULL))
		return value;

	apr_time_t now = apr_time_sec(apr_time_now());
	fuzz_freshen(payload, "iat", now);
	fuzz_freshen(payload, "exp", now + 600);

	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *cser = NULL;
	if ((oidc_util_key_symmetric_create(r, FUZZ_SHARED_SECRET, 0, NULL, TRUE, &jwk) == FALSE) || (jwk == NULL)) {
		oidc_json_decref(payload);
		return value;
	}
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, FALSE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	jwt->payload.value.json = payload;
	if (oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err) == TRUE)
		cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);

	return cser ? cser : value;
}

/* sign a "Bearer {...}" Authorization value in place of its payload */
static const char *fuzz_authorization_substitute(request_rec *r, const char *value) {
	const char *prefix = "Bearer ";
	if (strncmp(value, prefix, strlen(prefix)) != 0)
		return value;
	const char *token = fuzz_maybe_sign(r, value + strlen(prefix));
	return apr_pstrcat(r->pool, prefix, token, NULL);
}

/* sign an "access_token={...}" parameter (at a parameter boundary) in place of its payload */
static char *fuzz_param_substitute(request_rec *r, char *params) {
	const char *needle = "access_token=";
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
	const char *value = oidc_http_url_decode(r, end ? apr_pstrmemdup(r->pool, start, (apr_size_t)(end - start))
							: apr_pstrdup(r->pool, start));
	const char *token = fuzz_maybe_sign(r, value);
	if (token == value)
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
	 * environment tables: the handler scrubs and sets request headers and propagates claims */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.user = NULL;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	r.subprocess_env = r.subprocess_env ? apr_table_copy(pool, r.subprocess_env) : apr_table_make(pool, 8);
	apr_table_unset(r.headers_in, OIDC_HTTP_HDR_AUTHORIZATION);
	apr_table_unset(r.headers_in, "Cookie");

	const unsigned int sel = (size > 0) ? data[0] : 0;

	/* a per-input location config with the selected OIDCOAuthAcceptTokenAs set, installed in
	 * place of the fixture's for the duration of this input (the setter ORs into whatever is
	 * there, so a fresh config is the only way to select a subset) */
	oidc_dir_cfg_t *saved = ap_get_module_config(r.per_dir_config, &auth_openidc_module);
	oidc_dir_cfg_t *dir_cfg = oidc_cfg_dir_config_create(pool, NULL);
	for (unsigned int i = 0; i < sizeof(fuzz_accept_in) / sizeof(fuzz_accept_in[0]); i++)
		if (sel & (1u << i))
			oidc_cmd_dir_accept_oauth_token_in_set(fuzz_cmd(pool, &r, OIDCOAuthAcceptTokenAs), dir_cfg,
							       fuzz_accept_in[i]);
	ap_set_module_config(r.per_dir_config, &auth_openidc_module, dir_cfg);

	if (sel & 64) {
		r.method_number = M_OPTIONS;
		r.method = "OPTIONS";
	} else if (sel & 32) {
		r.method_number = M_POST;
		r.method = "POST";
		apr_table_set(r.headers_in, "Content-Type", "application/x-www-form-urlencoded");
	} else {
		r.method_number = M_GET;
		r.method = "GET";
	}

	/* the three sections */
	char *input = apr_pstrmemdup(pool, (const char *)(size > 0 ? data + 1 : data), size > 0 ? size - 1 : 0);
	char *authorization = input;
	char *args = NULL;
	char *cookie = NULL;
	char *nl = strchr(authorization, '\n');
	if (nl != NULL) {
		*nl = '\0';
		args = nl + 1;
		nl = strchr(args, '\n');
		if (nl != NULL) {
			*nl = '\0';
			cookie = nl + 1;
		}
	}
	if (authorization[0] != '\0')
		apr_table_set(r.headers_in, OIDC_HTTP_HDR_AUTHORIZATION,
			      fuzz_authorization_substitute(&r, authorization));
	r.args = args ? fuzz_param_substitute(&r, args) : NULL;
	/* the test stubs serve the POST body out of r->args */
	r.remaining = (apr_off_t)(r.args ? strlen(r.args) : 0);
	if (cookie != NULL)
		apr_table_set(r.headers_in, "Cookie", cookie);

	const char *token = NULL;
	oidc_oauth_get_bearer_token(&r, &token);
	oidc_oauth_check_userid(&r, cfg, NULL);

	ap_set_module_config(r.per_dir_config, &auth_openidc_module, saved);

	apr_pool_destroy(pool);
	return 0;
}
