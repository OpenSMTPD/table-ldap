/*
 * Copyright (c) 2024 Philipp Takacs <philipp@bureaucracy.de>
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "aldap.h"
#include "dict.h"
#include "log.h"
#include "table_stdio.h"
#include "util.h"

#ifndef MAXIMUM
#define MAXIMUM(a, b) ((a) > (b) ? (a) : (b))
#endif

enum {
	LDAP_ALIAS = 0,
	LDAP_DOMAIN,
	LDAP_CREDENTIALS,
	LDAP_NETADDR,
	LDAP_USERINFO,
	LDAP_SOURCE,
	LDAP_MAILADDR,
	LDAP_MAILADDRMAP,
	LDAP_ADDRNAME,

	LDAP_MAX
};

#define MAX_ATTRS	6

struct query {
	char	*filter;
	char	*attrs[MAX_ATTRS];
	size_t	 attrn;
};

struct query_result {
	char	**v[MAX_ATTRS];
};

static int ldap_run_query(int type, const char *, char *, size_t);

static char *config, *url, *username, *password, *basedn, *ca_file;

static struct aldap *aldap;
static struct query queries[LDAP_MAX];

static int
table_ldap_update(void)
{
	return 1;
}

static int
table_ldap_fetch(int service, struct dict *params, char *dst, size_t sz)
{
	return -1;
}

static struct aldap *
ldap_connect(const char *addr)
{
	struct aldap_url lu;
	struct aldap *ldap = NULL;
	struct tls_config *tls_config = NULL;
	struct addrinfo	 hints, *res0, *res;
	int		 error, fd = -1;

	if (aldap_parse_url(addr, &lu) != 1) {
		log_warnx("warn: ldap_parse_url fail");
		goto out;
	}
	if (lu.protocol == LDAPI) {
		log_warnx("ldapi:// is not suported yet");
		goto out;
	}
	if (lu.protocol == LDAPTLS) {
		log_warnx("ldap+tls:// is not suported yet");
		goto out;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	log_debug("ldap connect to: %s:%s", lu.host, lu.port);
	error = getaddrinfo(lu.host, lu.port, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return NULL;
	if (error) {
		log_warnx("warn: could not parse \"%s:%s\": %s", lu.host,
		    lu.port, gai_strerror(error));
		return NULL;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
			ldap = aldap_init(fd);
			break;
		}

		close(fd);
		fd = -1;
	}

	if (!ldap) {
		log_debug("can not connect");
		goto out;
	}

	if (lu.protocol == LDAPS || lu.protocol == LDAPTLS) {
		tls_config = tls_config_new();
		if (!tls_config) {
			log_warn("warn: can not get tls_config");
			aldap_close(ldap);
			ldap = NULL;
			goto out;
		}
		if (ca_file && tls_config_set_ca_file(tls_config, ca_file) == -1) {
			log_warnx("warn: can't load ca file: %s", tls_config_error(tls_config));
			aldap_close(ldap);
			ldap = NULL;
			goto out;
		}
		if (aldap_tls(ldap, tls_config, lu.host) == -1) {
			log_warnx("warn: tls connection failed");
			aldap_close(ldap);
			ldap = NULL;
			goto out;
		}
	}

out:
	tls_config_free(tls_config);
	aldap_free_url(&lu);
	return ldap;
}

static int
read_value(char **store, const char *key, const char *value)
{
	log_debug("debug: reading key \"%s\" -> \"%s\"", key, value);
	if (*store) {
		log_warnx("warn: duplicate key %s", key);
		return 0;
	}
	if ((*store = strdup(value)) == NULL) {
		log_warn("warn: strdup");
		return 0;
	}
	return 1;
}

static int
ldap_parse_attributes(struct query *query, const char *key, const char *line,
    size_t expect)
{
	char	buffer[1024];
	char   *p;
	size_t	m, n;

	log_debug("debug: parsing attribute \"%s\" (%zu) -> \"%s\"", key,
	    expect, line);

	if (strlcpy(buffer, line, sizeof buffer) >= sizeof buffer)
		return 0;

	m = 1;
	for (p = buffer; *p; ++p) {
		if (*p == ',') {
			*p = 0;
			m++;
		}
	}
	if (expect != m)
		return 0;

	p = buffer;
	for (n = 0; n < expect; ++n)
		query->attrs[n] = NULL;
	for (n = 0; n < m; ++n) {
		query->attrs[n] = strdup(p);
		if (query->attrs[n] == NULL) {
			log_warnx("warn: strdup");
			return 0; /* XXX cleanup */
		}
		p += strlen(p) + 1;
		query->attrn++;
	}
	return 1;
}

static int
ldap_config(void)
{
	size_t		 sz = 0;
	ssize_t		 flen;
	FILE		*fp;
	char		*key, *value, *buf = NULL;
	int		 services = 0;

	if ((fp = fopen(config, "r")) == NULL) {
		log_warn("warn: \"%s\"", config);
		return 0;
	}

	while ((flen = getline(&buf, &sz, fp)) != -1) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';

		key = strip(buf);
		if (*key == '\0' || *key == '#')
			continue;
		value = key;
		strsep(&value, " \t:");
		if (value) {
			while (*value) {
				if (!isspace((unsigned char)*value) &&
				    !(*value == ':' && isspace((unsigned char)*(value + 1))))
					break;
				++value;
			}
			if (*value == '\0')
				value = NULL;
		}

		if (value == NULL) {
			log_warnx("warn: missing value for key %s", key);
			continue;
		}

		if (!strcmp(key, "url"))
			read_value(&url, key, value);
		else if (!strcmp(key, "username"))
			read_value(&username, key, value);
		else if (!strcmp(key, "password"))
			read_value(&password, key, value);
		else if (!strcmp(key, "basedn"))
			read_value(&basedn, key, value);
		else if (!strcmp(key, "ca_file"))
			read_value(&ca_file, key, value);
		else if (!strcmp(key, "alias_filter")) {
			read_value(&queries[LDAP_ALIAS].filter, key, value);
			services |= K_ALIAS;
		} else if (!strcmp(key, "alias_attributes")) {
			ldap_parse_attributes(&queries[LDAP_ALIAS],
			    key, value, 1);
		} else if (!strcmp(key, "credentials_filter")) {
			read_value(&queries[LDAP_CREDENTIALS].filter, key, value);
			services |= K_CREDENTIALS;
		} else if (!strcmp(key, "credentials_attributes")) {
			ldap_parse_attributes(&queries[LDAP_CREDENTIALS],
			    key, value, 2);
		} else if (!strcmp(key, "domain_filter")) {
			read_value(&queries[LDAP_DOMAIN].filter, key, value);
			services |= K_DOMAIN;
		} else if (!strcmp(key, "domain_attributes")) {
			ldap_parse_attributes(&queries[LDAP_DOMAIN],
			    key, value, 1);
		} else if (!strcmp(key, "userinfo_filter")) {
			read_value(&queries[LDAP_USERINFO].filter, key, value);
			services |= K_USERINFO;
		} else if (!strcmp(key, "userinfo_attributes")) {
			ldap_parse_attributes(&queries[LDAP_USERINFO],
			    key, value, 3);
		} else if (!strcmp(key, "mailaddr_filter")) {
			read_value(&queries[LDAP_MAILADDR].filter, key, value);
			services |= K_MAILADDR;
		} else if (!strcmp(key, "mailaddr_attributes")) {
			ldap_parse_attributes(&queries[LDAP_MAILADDR],
			    key, value, 1);
		} else if (!strcmp(key, "mailaddrmap_filter")) {
			read_value(&queries[LDAP_MAILADDRMAP].filter, key, value);
			services |= K_MAILADDRMAP;
		} else if (!strcmp(key, "mailaddrmap_attributes")) {
			ldap_parse_attributes(&queries[LDAP_MAILADDRMAP],
			    key, value, 1);
		} else if (!strcmp(key, "netaddr_filter")) {
			read_value(&queries[LDAP_NETADDR].filter, key, value);
			services |= K_NETADDR;
		} else if (!strcmp(key, "netaddr_attributes")) {
			ldap_parse_attributes(&queries[LDAP_NETADDR],
			    key, value, 1);
		} else
			log_warnx("warn: bogus entry \"%s\"", key);
	}

	if (!services) {
		log_warnx("warn: no service registered");
	}
	table_api_register_services(services);

	free(buf);
	fclose(fp);
	return 1;
}

static int
ldap_open(void)
{
	struct aldap_message	*amsg = NULL;

	if (aldap) {
		aldap_close(aldap);
		log_info("info: table-ldap: closed previous connection");
	}

	aldap = ldap_connect(url);
	if (aldap == NULL) {
		log_warnx("warn: ldap_connect error");
		goto err;
	}

	if (aldap_bind(aldap, username, password) == -1) {
		log_warnx("warn: aldap_bind error");
		goto err;
	}

	if ((amsg = aldap_parse(aldap)) == NULL) {
		log_warnx("warn: aldap_parse");
		goto err;
	}

	switch (aldap_get_resultcode(amsg)) {
	case LDAP_SUCCESS:
		log_debug("debug: ldap server accepted credentials");
		break;
	case LDAP_INVALID_CREDENTIALS:
		log_warnx("warn: ldap server refused credentials");
		goto err;
	default:
		log_warnx("warn: failed to bind, result #%d",
		    aldap_get_resultcode(amsg));
		goto err;
	}

	if (amsg)
		aldap_freemsg(amsg);
	return 1;

err:
	if (aldap)
		aldap_close(aldap);
	if (amsg)
		aldap_freemsg(amsg);
	return 0;
}

static int
table_ldap_lookup(int service, struct dict *params, const char *key, char *dst, size_t sz)
{
	int ret;

	switch(service) {
	case K_ALIAS:
	case K_DOMAIN:
	case K_CREDENTIALS:
	case K_USERINFO:
	case K_MAILADDR:
	case K_MAILADDRMAP:
	case K_NETADDR:
		if ((ret = ldap_run_query(service, key, dst, sz)) >= 0) {
			return ret;
		}
		log_debug("debug: table-ldap: reconnecting");
		if (!ldap_open()) {
			log_warnx("warn: table-ldap: failed to connect");
			return -1;
		}
		return ldap_run_query(service, key, dst, sz);
	default:
		return -1;
	}
}

static int
realloc_results(struct query_result **r, size_t *num)
{
	struct query_result *new;
	size_t newsize = MAXIMUM(1, (*num)*2);
	if ((new = reallocarray(*r, newsize, sizeof(**r))) == NULL)
		return 0;
	*num = newsize;
	*r = new;
	return 1;
}

static int
ldap_query(const char *filter, const char *key, char **attributes, size_t attrn, struct query_result **results, size_t *nresults)
{
	struct aldap_message		*m = NULL;
	struct aldap_page_control	*pg = NULL;
	struct aldap_stringset		*ldap_res;
	struct query_result		*res = NULL;
	int				 ret;
	size_t				 i, j, k, found = 0, nres = 0;

	do {
		ret = -1;
		if (aldap_search(aldap, basedn, LDAP_SCOPE_SUBTREE,
		    filter, key, attributes, 0, 0, 0, pg) == -1) {
			goto end;
		}
		if (pg != NULL) {
			aldap_freepage(pg);
			pg = NULL;
		}

		while ((m = aldap_parse(aldap)) != NULL) {
			if (aldap->msgid != m->msgid)
				goto end;
			if (m->message_type == LDAP_RES_SEARCH_RESULT) {
				if (m->page != NULL && m->page->cookie_len)
					pg = m->page;
				aldap_freemsg(m);
				m = NULL;
				ret = 0;
				break;
			}
			if (m->message_type != LDAP_RES_SEARCH_ENTRY)
				goto end;

			if (found >= nres) {
				if (!realloc_results(&res, &nres)) {
					goto end;
				}
			}
			memset(&res[found], 0, sizeof(res[found]));
			for (i = 0; i < attrn; ++i) {
				if (aldap_match_attr(m, attributes[i], &ldap_res) != 1) {
					goto end;
				}
				res[found].v[i] = calloc(ldap_res->len + 1, sizeof(*res[found].v[i]));
				for (j = 0; j < ldap_res->len; j++) {
					res[found].v[i][j] = strndup(ldap_res->str[j].ostr_val, ldap_res->str[j].ostr_len);
				}
				aldap_free_attr(ldap_res);
			}
			aldap_freemsg(m);
			m = NULL;
			found++;
		}
	} while (pg != NULL);

end:
	if (ret == -1) {
		for (i = 0; i < found; i++) {
			for (j = 0; j < attrn; j++) {
				for (k = 0; res[i].v[j][k]; k++) {
					free(res[i].v[j][k]);
				}
				free(res[i].v[j]);
			}
		}
		free(res);
	} else {
		ret = found ? 1 : 0;
		*results = res;
		*nresults = found;
	}

	if (m)
		aldap_freemsg(m);
	log_debug("debug: table_ldap: ldap_query: filter=%s, key=%s, ret=%d", filter, key, ret);
	return ret;
}

static int
ldap_run_query(int type, const char *key, char *dst, size_t sz)
{
	struct query	 	*q;
	struct query_result	*res = NULL;
	int		  	 ret;
	size_t			 i, j, k, nres = 0;
	char			*r, *user, *pwhash, *uid, *gid, *home;

	switch (type) {
	case K_ALIAS:		q = &queries[LDAP_ALIAS];	break;
	case K_DOMAIN:		q = &queries[LDAP_DOMAIN];	break;
	case K_CREDENTIALS:	q = &queries[LDAP_CREDENTIALS];	break;
	case K_NETADDR:		q = &queries[LDAP_NETADDR];	break;
	case K_USERINFO:	q = &queries[LDAP_USERINFO];	break;
	case K_SOURCE:		q = &queries[LDAP_SOURCE];	break;
	case K_MAILADDR:	q = &queries[LDAP_MAILADDR];	break;
	case K_MAILADDRMAP:	q = &queries[LDAP_MAILADDRMAP];	break;
	case K_ADDRNAME:	q = &queries[LDAP_ADDRNAME];	break;
	default:
		return -1;
	}

	if (!q->filter) {
		/* XXX get the string of the type */
		log_warnx("warn: query %d without a filter configured", type);
		return -1;
	}

	ret = ldap_query(q->filter, key, q->attrs, q->attrn, &res, &nres);
	if (ret <= 0 || dst == NULL)
		goto end;

	switch (type) {

	case K_ALIAS:
	case K_MAILADDRMAP:
		memset(dst, 0, sz);
		for (i = 0; ret != -1 && i < nres; i++) {
			for (j = 0; res[i].v[0][j]; j++) {
				if ((i || j) && strlcat(dst, ", ", sz) >= sz) {
					ret = -1;
					break;
				}
				if (strlcat(dst, res[i].v[0][j], sz) >= sz) {
					ret = -1;
					break;
				}
			}
		}
		break;
	case K_DOMAIN:
	case K_MAILADDR:
		r = res[0].v[0][0];
		if (!r || strlcpy(dst, r, sz) >= sz)
			ret = -1;
		break;
	case K_CREDENTIALS:
		user = res[0].v[0][0];
		pwhash = res[0].v[1][0];
		if (!user || !pwhash || snprintf(dst, sz, "%s:%s", user, pwhash) >= (int)sz)
			ret = -1;
		break;
	case K_USERINFO:
		uid = res[0].v[0][0];
		gid = res[0].v[1][0];
		home = res[0].v[2][0];
		if (!uid || !gid || !home || snprintf(dst, sz, "%s:%s:%s", uid, gid, home) >= (int)sz)
			ret = -1;
		break;
	default:
		log_warnx("warn: unsupported lookup kind");
		ret = -1;
	}

	if (ret == -1)
		log_warnx("warn: could not format result");

end:
	for (i = 0; i < nres; i++) {
		for (j = 0; j < q->attrn; ++j) {
			for (k = 0; res[i].v[j][k]; k++) {
				free(res[i].v[j][k]);
			}
			free(res[i].v[j]);
		}
	}
	free(res);

	return ret;
}

static int
table_ldap_check(int service, struct dict *params, const char *key)
{
	int ret;

	switch(service) {
	case K_ALIAS:
	case K_DOMAIN:
	case K_CREDENTIALS:
	case K_USERINFO:
	case K_MAILADDR:
	case K_MAILADDRMAP:
	case K_NETADDR:
		if ((ret = ldap_run_query(service, key, NULL, 0)) >= 0) {
			return ret;
		}
		log_debug("debug: table-ldap: reconnecting");
		if (!ldap_open()) {
			log_warnx("warn: table-ldap: failed to connect");
			return -1;
		}
		return ldap_run_query(service, key, NULL, 0);
	default:
		return -1;
	}
}

int
main(int argc, char **argv)
{
	int ch;

	log_init(1);
	log_setverbose(~0);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			fatalx("bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		fatalx("bogus argument(s)");

	config = argv[0];

	if (!ldap_config())
		fatalx("could not parse config");
	log_debug("debug: done reading config");

	if (!ldap_open())
		fatalx("failed to connect");
	log_debug("debug: connected");

	table_api_on_update(table_ldap_update);
	table_api_on_check(table_ldap_check);
	table_api_on_lookup(table_ldap_lookup);
	table_api_on_fetch(table_ldap_fetch);
	table_api_dispatch();

	return 0;
}
