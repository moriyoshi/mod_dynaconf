#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_strings.h"

#include <stdio.h>

typedef struct dynaconf_cfg {
    ap_directive_t *first;
    ap_directive_t *last;
} dynaconf_cfg;

module AP_MODULE_DECLARE_DATA dynaconf_module;

static dynaconf_cfg *dynaconf_dconfig(const request_rec *r)
{
    return (dynaconf_cfg *) ap_get_module_config(r->per_dir_config, &dynaconf_module);
}

static const char *cmd_dynamic_configuration(cmd_parms *cmd, void *mconfig,
                                             const char *args)
{
    dynaconf_cfg *cfg = (dynaconf_cfg *) mconfig;
    ap_directive_t *next = apr_pcalloc(cmd->pool, sizeof(ap_directive_t));
    apr_ssize_t directive_len;
    {
        const char *p = args, *d;
        while (*p == '\t' || *p == ' ') p++;
        if (!*p)
            return apr_pstrdup(cmd->pool, "directive name must be specified");
        d = p;
        while (*p != '\t' && *p != ' ' && *p) p++;
        directive_len = p - d;
        next->directive = apr_pstrndup(cmd->pool, d, directive_len);
        while (*p == '\t' || *p == ' ') p++;
        if (!*p)
            return apr_pstrdup(cmd->pool, "at lease one argument is needed");
        next->args = apr_pstrdup(cmd->pool, p);
    }
    next->next = NULL;
    next->first_child = NULL;
    next->parent = NULL;
    next->data = NULL;
    next->filename = NULL;
    next->line_num = 0;

    if (cfg->last)
        cfg->last->next = next;
    else
        cfg->first = next;
    cfg->last = next;
    return NULL;
}

static void *dynaconf_create_dir_config(apr_pool_t *p, char *dirspec)
{
    dynaconf_cfg *cfg = apr_pcalloc(p, sizeof(dynaconf_cfg));
    cfg->first = cfg->last = NULL;
    return (void *) cfg;
}

static void *dynaconf_merge_dir_config(apr_pool_t *p, void *parent_conf,
                                      void *newloc_conf)
{

    dynaconf_cfg *merged_config = (dynaconf_cfg *) apr_pcalloc(p, sizeof(dynaconf_cfg));
    dynaconf_cfg *pconf = (dynaconf_cfg *) parent_conf;
    dynaconf_cfg *nconf = (dynaconf_cfg *) newloc_conf;
    ap_directive_t *i;
    
    merged_config->first = merged_config->last = NULL;

    for (i = pconf->first; i; i = i->next) {
        ap_directive_t *next = apr_pmemdup(p, i, sizeof(*i));
        next->next = NULL;

        if (merged_config->last)
            merged_config->last->next = next;
        else
            merged_config->first = next;
        merged_config->last = next;
    }

    for (i = nconf->first; i; i = i->next) {
        ap_directive_t *next = apr_pmemdup(p, i, sizeof(*i));
        next->next = NULL;

        if (merged_config->last)
            merged_config->last->next = next;
        else
            merged_config->first = next;
        merged_config->last = next;
    }

    return (void *) merged_config;
}

static void *dynaconf_create_server_config(apr_pool_t *p, server_rec *s)
{
    dynaconf_cfg *cfg = (dynaconf_cfg *) apr_pcalloc(p, sizeof(dynaconf_cfg));
    cfg->first = cfg->last = NULL;
    return (void *) cfg;
}

static void *dynaconf_merge_server_config(apr_pool_t *p, void *server1_conf,
                                         void *server2_conf)
{
    dynaconf_merge_dir_config(p, server1_conf, server2_conf);
}

static const char * resolve_env(request_rec *r, const char *word)
{
    apr_pool_t *p = r->pool;
# define SMALL_EXPANSION 5
    struct sll {
        struct sll *next;
        const char *string;
        apr_size_t len;
    } *result, *current, sresult[SMALL_EXPANSION];
    char *res_buf, *cp;
    const char *s, *e, *ep;
    unsigned spc;
    apr_size_t outlen;

    s = ap_strchr_c(word, '$');
    if (!s) {
        return word;
    }

    /* well, actually something to do */
    ep = word + strlen(word);
    spc = 0;
    result = current = &(sresult[spc++]);
    current->next = NULL;
    current->string = word;
    current->len = s - word;
    outlen = current->len;

    do {
        /* prepare next entry */
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (struct sll *)apr_palloc(p,
                                                       sizeof(*current->next));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        if (*s == '$') {
            if (s[1] == '{' && (e = ap_strchr_c(s, '}'))) {
                word = apr_table_get(r->subprocess_env, apr_pstrndup(p, s+2, e-s-2));
                if (word) {
                    current->string = word;
                    current->len = strlen(word);
                    outlen += current->len;
                }
                else {
                    current->string = s;
                    current->len = 0;
                }
                s = e + 1;
            }
            else {
                current->string = s++;
                current->len = 1;
                ++outlen;
            }
        }
        else {
            word = s;
            s = ap_strchr_c(s, '$');
            current->string = word;
            current->len = s ? s - word : ep - word;
            outlen += current->len;
        }
    } while (s && *s);

    /* assemble result */
    res_buf = cp = apr_palloc(p, outlen + 1);
    do {
        if (result->len) {
            memcpy(cp, result->string, result->len);
            cp += result->len;
        }
        result = result->next;
    } while (result);
    res_buf[outlen] = '\0';

    return res_buf;
}

static int dynaconf_translate_handler(request_rec *r)
{
    dynaconf_cfg *cfg = dynaconf_dconfig(r);
    cmd_parms parms = {NULL, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    const char *errmsg;
    ap_directive_t *i, *first = NULL, *last = NULL;

    for (i = cfg->first; i; i = i->next) {
        ap_directive_t *next = apr_pmemdup(r->pool, i, sizeof(*i));
        next->args = resolve_env(r, next->args);
        next->next = NULL;

        if (last)
            last->next = next;
        else
            first = next;
        last = next;
    }

    parms.override = OR_ALL|ACCESS_CONF;
    parms.override_opts = OR_ALL;
    parms.directive = first;
    parms.path = apr_pstrdup(r->pool, r->filename);
    parms.pool = r->pool;
    parms.temp_pool = r->pool;
    parms.server = r->server;

    errmsg = ap_walk_config(parms.directive, &parms, r->per_dir_config);
    if (errmsg)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "mod_dynaconf: %s", errmsg);
    return DECLINED;
}

static void dynaconf_register_hooks(apr_pool_t *p)
{
    //ap_hook_translate_name(dynaconf_translate_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_fixups(dynaconf_translate_handler, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec dynaconf_cmds[] =
{
    AP_INIT_RAW_ARGS(
        "DynamicConfiguration",             /* directive name */
        cmd_dynamic_configuration,          /* config action routine */
        NULL,                               /* argument to include in call */
        OR_ALL,                             /* where available */
        "DynamicConfiguration [directive name] [args...]"  /* directive description */
    ),
    {NULL}
};

module AP_MODULE_DECLARE_DATA dynaconf_module =
{
    STANDARD20_MODULE_STUFF,
    dynaconf_create_dir_config,    /* per-directory config creator */
    dynaconf_merge_dir_config,     /* dir config merger */
    dynaconf_create_server_config, /* server config creator */
    dynaconf_merge_server_config,  /* server config merger */
    dynaconf_cmds,                 /* command table */
    dynaconf_register_hooks,       /* set up other request processing hooks */
};

/*
 * vim: sts=4 sw=4 ts=4 et
 */
