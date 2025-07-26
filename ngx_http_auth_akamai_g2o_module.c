/*
 * nginx (c) Igor Sysoev
 * ngx_http_accesskey_module (C) Mykola Grechukh <gns@altlinux.org>
 * adapted to Akamai G2O (C) Tim Macfarlane <timmacfarlane@gmail.com>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


#define NGX_HTTP_AUTH_AKAMAI_GEO_MODE_OFF            0  /* no G2O validation */
#define NGX_HTTP_AUTH_AKAMAI_GEO_MODE_DRY_RUN        1  /* validate G2O but don't fail any requests */
#define NGX_HTTP_AUTH_AKAMAI_GEO_MODE_ON             2  /* validate G2O and fail the request if invalid */


typedef struct {
    ngx_uint_t                  mode;
    ngx_http_complex_value_t   *nonce;
    ngx_http_complex_value_t   *key;
    ngx_str_t                   data_header;
    ngx_str_t                   sign_header;
    const EVP_MD             *(*hash_function)(void);
    ngx_uint_t                  version;
    time_t                      time_window;
    ngx_uint_t                  log_level;
} ngx_http_auth_akamai_g2o_loc_conf_t;


static ngx_int_t ngx_http_auth_akamai_g2o_handler(ngx_http_request_t *r);

static void *ngx_http_auth_akamai_g2o_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_akamai_g2o_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_auth_akamai_g2o_hash_function(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_akamai_g2o_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_auth_akamai_g2o_base64_signature_of_data(
    ngx_http_request_t *r, ngx_str_t data, ngx_str_t key, u_char *signature);
static ngx_int_t ngx_http_auth_akamai_g2o_get_auth_data_fields(ngx_str_t data,
    u_int *version, u_int *time, ngx_str_t *nonce);


static ngx_conf_enum_t  ngx_http_auth_akamai_g2o_mode[] = {
    { ngx_string("off"), NGX_HTTP_AUTH_AKAMAI_GEO_MODE_OFF },
    { ngx_string("dry_run"), NGX_HTTP_AUTH_AKAMAI_GEO_MODE_DRY_RUN },
    { ngx_string("on"), NGX_HTTP_AUTH_AKAMAI_GEO_MODE_ON },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  ngx_http_auth_akamai_g2o_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_auth_akamai_g2o_version_bounds = {
    ngx_conf_check_num_bounds, 1, 5
};


static ngx_command_t  ngx_http_auth_akamai_g2o_commands[] = {

    { ngx_string("auth_akamai_g2o"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, mode),
      &ngx_http_auth_akamai_g2o_mode },

    { ngx_string("auth_akamai_g2o_nonce"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, nonce),
      NULL },

    { ngx_string("auth_akamai_g2o_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, key),
      NULL },

    { ngx_string("auth_akamai_g2o_data_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, data_header),
      NULL },

    { ngx_string("auth_akamai_g2o_sign_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, sign_header),
      NULL },

    { ngx_string("auth_akamai_g2o_hash_function"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_akamai_g2o_hash_function,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_akamai_g2o_version"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, version),
      &ngx_http_auth_akamai_g2o_version_bounds },

    { ngx_string("auth_akamai_g2o_time_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, time_window),
      NULL },

    { ngx_string("auth_akamai_g2o_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_akamai_g2o_loc_conf_t, log_level),
      &ngx_http_auth_akamai_g2o_log_levels },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_akamai_g2o_module_ctx = {
    NULL,                                           /* preconfiguration */
    ngx_http_auth_akamai_g2o_init,                  /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_auth_akamai_g2o_create_loc_conf,       /* create location configuration */
    ngx_http_auth_akamai_g2o_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_auth_akamai_g2o_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_akamai_g2o_module_ctx,           /* module context */
    ngx_http_auth_akamai_g2o_commands,              /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_auth_akamai_g2o_get_data_and_sign(ngx_http_request_t *r,
    ngx_str_t *header_data, ngx_str_t *header_sign)
{
    ngx_http_auth_akamai_g2o_loc_conf_t  *alcf;
    ngx_list_t headers = r->headers_in.headers;
    ngx_list_part_t *part = &headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_table_elt_t header;

    unsigned int i;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_akamai_g2o_module);

    for (i = 0 ;; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

        header = data[i];
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s: %s",
                       header.key.data, header.value.data);

        if (ngx_strcasecmp(alcf->data_header.data, header.key.data) == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "found %V", &alcf->data_header);
            *header_data = header.value;
        }

        if (ngx_strcasecmp(alcf->sign_header.data, header.key.data) == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "found %V", &alcf->sign_header);
            *header_sign = header.value;
        }
    }
}


static ngx_int_t
ngx_http_auth_akamai_g2o_check_headers(ngx_http_request_t *r,
    ngx_http_auth_akamai_g2o_loc_conf_t *alcf)
{
    ngx_str_t key, nonce;

    if (ngx_http_complex_value(r, alcf->key, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    /* if the key evaluates to an empty string, don't perform any validation */
    if (!key.len) {
        return 1;
    }

    if (ngx_http_complex_value(r, alcf->nonce, &nonce) != NGX_OK) {
        return NGX_ERROR;
    }

    /* if the nonce evaluates to an empty string, don't perform any validation */
    if (!nonce.len) {
        return 1;
    }

    ngx_str_t header_data = ngx_null_string, header_sign = ngx_null_string;

    ngx_http_auth_akamai_g2o_get_data_and_sign(r, &header_data, &header_sign);

    if (!header_data.data) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o missing data header");
        return NGX_ERROR;
    }

    if (!header_sign.data) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o missing sign header");
        return NGX_ERROR;
    }

    u_int version, auth_time;
    ngx_str_t header_nonce;

    if (ngx_http_auth_akamai_g2o_get_auth_data_fields(header_data, &version,
            &auth_time, &header_nonce) != NGX_OK)
    {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o data not formatted correctly \"%V\"", &header_data);
        return NGX_ERROR;
    }

    time_t current_time = ngx_time();

    /* request using correct version of G2O */
    if (version != alcf->version) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o version \"%ud\" invalid", version);
        return NGX_ERROR;
    }

    /* request not too far into the future */
    if (auth_time > current_time + alcf->time_window) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o auth time \"%ud\" too far into the future", auth_time);
        return NGX_ERROR;
    }

    /* request not too old */
    if (auth_time < current_time - alcf->time_window) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o auth time \"%ud\" too old", auth_time);
        return NGX_ERROR;
    }

    /* nonce is correct */
    if (nonce.len != header_nonce.len
        || ngx_memcmp(header_nonce.data, nonce.data, nonce.len))
    {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o nonce \"%V\" incorrect", &header_nonce);
        return NGX_ERROR;
    }

    /* for base64 we need: ceiling(32 / 3) * 4 + 1 = 45 bytes */
    /* where 32 is SHA256 digest length                       */
    /* + 1 for the string termination char                    */
    /* lets call it 60, just in case                          */
    u_char signature[60];

    /* signature is correct */
    if (ngx_http_auth_akamai_g2o_base64_signature_of_data(r, header_data,
                                                          key, signature)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_strncmp(header_sign.data, signature, header_sign.len)) {
        ngx_log_error(alcf->log_level, r->connection->log, 0,
                      "g2o signature incorrect, expected \"%s\", got \"%V\"",
                      signature, &header_sign);
        return NGX_ERROR;
    }

    /* request past all checks, content is good to go! */
    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_akamai_g2o_base64_signature_of_data(ngx_http_request_t *r,
    ngx_str_t data, ngx_str_t key, u_char *signature)
{
    ngx_http_auth_akamai_g2o_loc_conf_t  *alcf;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    ngx_str_t base64_dest;
    ngx_str_t base64_src;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX hmac_buf;
#endif
    HMAC_CTX *hmac;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_akamai_g2o_module);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        return NGX_ERROR;
    }
#else
    hmac = &hmac_buf;
    HMAC_CTX_init(hmac);
#endif
    HMAC_Init_ex(hmac, key.data, key.len, alcf->hash_function(), NULL);
    HMAC_Update(hmac, data.data, data.len);
    HMAC_Update(hmac, r->unparsed_uri.data, r->unparsed_uri.len);
    HMAC_Final(hmac, md, &md_len);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    HMAC_CTX_free(hmac);
#else
    HMAC_CTX_cleanup(hmac);
#endif

    base64_src.data = md;
    base64_src.len = md_len;
    base64_dest.data = signature;

    ngx_encode_base64(&base64_dest, &base64_src);
    base64_dest.data[base64_dest.len] = '\0';

    return NGX_OK;
}


static u_char *
ngx_http_auth_akamai_g2o_get_next_auth_data_token(u_char *start,
    u_char *end, ngx_str_t *output)
{
    output->data = start;
    for (; start + 1 < end; start++) {
        if (start[0] == ',' && start[1] == ' ')
        {
            output->len = start - output->data;
            return start + 2;
        }
    }
    output->len = end - output->data;
    return end;
}


static ngx_int_t
ngx_http_auth_akamai_g2o_get_auth_data_fields(ngx_str_t data, u_int *version,
    u_int *time, ngx_str_t *nonce)
{
    u_char *p = data.data;
    u_char *end = data.data + data.len;
    ngx_str_t cur_token;

    /* version */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, &cur_token);
    if (cur_token.len == 0) {
        return NGX_ERROR;
    }
    *version = ngx_atoi(cur_token.data, cur_token.len);

    /* ghost ip */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, &cur_token);
    if (cur_token.len == 0) {
        return NGX_ERROR;
    }

    /* client ip */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, &cur_token);
    if (cur_token.len == 0) {
        return NGX_ERROR;
    }

    /* time */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, &cur_token);
    if (cur_token.len == 0) {
        return NGX_ERROR;
    }
    *time = ngx_atoi(cur_token.data, cur_token.len);

    /* unique id */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, &cur_token);
    if (cur_token.len == 0) {
        return NGX_ERROR;
    }

    /* nonce */
    p = ngx_http_auth_akamai_g2o_get_next_auth_data_token(p, end, nonce);
    if (nonce->len == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_akamai_g2o_handler(ngx_http_request_t *r)
{
    ngx_http_auth_akamai_g2o_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_akamai_g2o_module);

    switch (alcf->mode) {
    case NGX_HTTP_AUTH_AKAMAI_GEO_MODE_OFF:
        break;

    case NGX_HTTP_AUTH_AKAMAI_GEO_MODE_ON:
        if (ngx_http_auth_akamai_g2o_check_headers(r, alcf) != NGX_OK) {
            ngx_log_error(alcf->log_level, r->connection->log, 0,
                          "g2o auth failed, mode: on");
            return NGX_HTTP_FORBIDDEN;
        }
        break;

    case NGX_HTTP_AUTH_AKAMAI_GEO_MODE_DRY_RUN:
        if (ngx_http_auth_akamai_g2o_check_headers(r, alcf) != NGX_OK) {
            ngx_log_error(alcf->log_level, r->connection->log, 0,
                          "g2o auth failed, mode: dry_run");
        }
        break;
    }

    return NGX_OK;
}


static char *
ngx_http_auth_akamai_g2o_hash_function(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_akamai_g2o_loc_conf_t    *alcf = conf;

    ngx_str_t   *value;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "md5") == 0) {
        alcf->hash_function = EVP_md5;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "sha1") == 0) {
        alcf->hash_function = EVP_sha1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "sha256") == 0) {
        alcf->hash_function = EVP_sha256;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"%s\" in \"%s\" directive, "
            "it must be \"md5\", \"sha1\" or \"sha256\"",
            value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_auth_akamai_g2o_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_akamai_g2o_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_akamai_g2o_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->hash_function = NGX_CONF_UNSET_PTR;
    conf->version = NGX_CONF_UNSET_UINT;
    conf->time_window = NGX_CONF_UNSET;
    conf->log_level = NGX_CONF_UNSET_UINT;
    return conf;
}


static char *
ngx_http_auth_akamai_g2o_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_auth_akamai_g2o_loc_conf_t  *prev = parent;
    ngx_http_auth_akamai_g2o_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode,
        NGX_HTTP_AUTH_AKAMAI_GEO_MODE_OFF);

    if (conf->key == NULL) {
        conf->key = prev->key;
    }

    if (conf->nonce == NULL) {
        conf->nonce = prev->nonce;
    }

    ngx_conf_merge_str_value(conf->data_header, prev->data_header,
        "X-Akamai-G2O-Auth-Data");
    ngx_conf_merge_str_value(conf->sign_header, prev->sign_header,
        "X-Akamai-G2O-Auth-Sign");
    ngx_conf_merge_ptr_value(conf->hash_function, prev->hash_function,
        EVP_md5);
    ngx_conf_merge_uint_value(conf->version, prev->version, 3);
    ngx_conf_merge_value(conf->time_window, prev->time_window, 30);
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);

    if (conf->mode != NGX_HTTP_AUTH_AKAMAI_GEO_MODE_OFF) {

        if (!conf->key) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "auth_akamai_g2o_key not configured");
            return NGX_CONF_ERROR;
        }

        if (!conf->nonce) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "auth_akamai_g2o_nonce not configured");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_akamai_g2o_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_akamai_g2o_handler;

    return NGX_OK;
}
