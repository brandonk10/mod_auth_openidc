/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2017-2023 ZmartZone Holding BV
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef MOD_AUTH_OPENIDC_METRICS_H_
#define MOD_AUTH_OPENIDC_METRICS_H_

apr_byte_t oidc_metrics_cache_post_config(server_rec *s);
apr_status_t oidc_metrics_cache_child_init(apr_pool_t *p, server_rec *s);
apr_status_t oidc_metrics_cache_cleanup(server_rec *s);
int oidc_metrics_handle_request(request_rec *r);

typedef enum { OM_AUTHN_REQUEST = 0, OM_AUTHN_RESPONSE, OM_SESSION_VALID } oidc_metrics_timing_type_t;

typedef struct oidc_metrics_timing_info_t {
	oidc_metrics_timing_type_t type;
	char *name;
	char *subkey;
	char *desc;
} oidc_metrics_timing_info_t;

extern const oidc_metrics_timing_info_t _oidc_metrics_timings_info[];

void oidc_metrics_timing_add(request_rec *r, oidc_metrics_timing_type_t type, apr_time_t elapsed);

#define OIDC_METRICS_TIMING_START(r, cfg)                                                                              \
	apr_time_t _oidc_metrics_tstart;                                                                               \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		_oidc_metrics_tstart = apr_time_now();

#define OIDC_METRICS_TIMING_ADD(r, cfg, type)                                                                          \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		if (apr_hash_get(cfg->metrics_hook_data, _oidc_metrics_timings_info[type].name,                        \
				 APR_HASH_KEY_STRING) != NULL)                                                         \
			oidc_metrics_timing_add(r, type, apr_time_now() - _oidc_metrics_tstart);

typedef enum {

	OM_AUTHTYPE_OPENID_CONNECT = 0,
	OM_AUTHTYPE_OAUTH20,
	OM_AUTHTYPE_AUTH_OPENIDC,
	OM_AUTHTYPE_DECLINED,

	OM_SESSION_ERROR_COOKIE_DOMAIN,
	OM_SESSION_ERROR_EXPIRED,
	OM_SESSION_ERROR_REFRESH_ACCESS_TOKEN,
	OM_SESSION_ERROR_REFRESH_USERINFO,
	OM_SESSION_ERROR_GENERAL,

	OM_AUTHN_REQUEST_ERROR_URL,

	OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH,
	OM_AUTHN_RESPONSE_ERROR_STATE_EXPIRED,
	OM_AUTHN_RESPONSE_ERROR_PROVIDER,
	OM_AUTHN_RESPONSE_ERROR_PROTOCOL,
	OM_AUTHN_RESPONSE_ERROR_REMOTE_USER,

	OM_REDIRECT_URI_AUTHN_RESPONSE_REDIRECT,
	OM_REDIRECT_URI_AUTHN_RESPONSE_POST,
	OM_REDIRECT_URI_AUTHN_RESPONSE_IMPLICIT,
	OM_REDIRECT_URI_DISCOVERY_RESPONSE,
	OM_REDIRECT_URI_REQUEST_LOGOUT,
	OM_REDIRECT_URI_REQUEST_JWKS,
	OM_REDIRECT_URI_REQUEST_SESSION,
	OM_REDIRECT_URI_REQUEST_REFRESH,
	OM_REDIRECT_URI_REQUEST_REQUEST_URI,
	OM_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE,
	OM_REDIRECT_URI_REQUEST_REVOKE_SESSION,
	OM_REDIRECT_URI_REQUEST_INFO,
	OM_REDIRECT_URI_ERROR_PROVIDER,
	OM_REDIRECT_URI_ERROR_INVALID,

	OM_CONTENT_REQUEST_DECLINED,
	OM_CONTENT_REQUEST_INFO,
	OM_CONTENT_REQUEST_JWKS,
	OM_CONTENT_REQUEST_DISCOVERY,
	OM_CONTENT_REQUEST_POST_PRESERVE,
	OM_CONTENT_REQUEST_UNKNOWN,

} oidc_metrics_counter_type_t;

typedef struct oidc_metrics_counter_info_t {
	oidc_metrics_counter_type_t type;
	char *name;
	char *label_name;
	char *label_value;
	char *desc;
} oidc_metrics_counter_info_t;

extern const oidc_metrics_counter_info_t _oidc_metrics_counters_info[];

void oidc_metrics_counter_inc(request_rec *r, oidc_metrics_counter_type_t type);

#define OIDC_METRICS_COUNTER_INC(r, cfg, type)                                                                         \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		if (apr_hash_get(cfg->metrics_hook_data, _oidc_metrics_counters_info[type].name,                       \
				 APR_HASH_KEY_STRING) != NULL)                                                         \
			oidc_metrics_counter_inc(r, type);

#endif /* MOD_AUTH_OPENIDC_METRICS_H_ */
