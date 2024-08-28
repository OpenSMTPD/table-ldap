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
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "ber.h"
#include "aldap.h"
#include "dict.h"
#include "log.h"
#include "table_api.h"
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

static int ldap_open(void);
static struct query * lookup_query(int type);
static void ldap_lookup_entry(const struct request *req, const struct aldap_message *m);
static struct aldap *ldap_connect(const char *addr);
static void ldap_handle_response(const char *ldapid, const struct aldap_message *m, struct request *req);
static void ldap_fd_callback(int fd, short revents);
static int read_value(char **store, const char *key, const char *value);

static char *config, *url, *username, *password, *basedn, *ca_file;
static struct dict	requests;

static struct aldap *aldap;
static struct query queries[LDAP_MAX];

static char *ldap_dn_attr[2] = { "dn", NULL };


static struct aldap *
ldap_connect(const char *addr)
{
	struct aldap_url lu;
	struct aldap *ldap = NULL;
	struct tls_config *tls_config = NULL;
	struct addrinfo	 hints, *res0, *res;
	int		 error, fd = -1;
	int		 flags;

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

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

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

static void
ldap_lookup_entry(const struct request *req, const struct aldap_message *m)
{
	struct aldap_stringset *attr = NULL;
	struct query *q = lookup_query(req->s);
	char tmp[BUFSIZ];

	switch (req->s) {
	case K_ALIAS:
	case K_MAILADDRMAP:
		if (aldap_match_attr(m, q->attrs[0], &attr) == -1) {
			return;
		}
		for (size_t i = 0; i < attr->len; i++) {
			table_api_lookup_result(req->id, req->s, attr->str[i].ostr_val);
		}
		aldap_free_attr(attr);
		break;
	case K_DOMAIN:
	case K_MAILADDR:
		if (aldap_match_attr(m, q->attrs[0], &attr) == -1) {
			break;
		}
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[0]);
		table_api_lookup_result(req->id, req->s, attr->str[0].ostr_val);
		aldap_free_attr(attr);
		break;
	case K_CREDENTIALS:
		if (aldap_match_attr(m, q->attrs[0], &attr) == -1)
			break;
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[1]);
		if (strlcat(tmp, attr->str[0].ostr_val, sizeof(tmp)) > sizeof(tmp))
			break;
		if (strlcat(tmp, ":", sizeof(tmp)) > sizeof(tmp))
			break;
		aldap_free_attr(attr);
		if (aldap_match_attr(m, q->attrs[1], &attr) == -1)
			break;
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[1]);
		if (strlcat(tmp, attr->str[1].ostr_val, sizeof(tmp)) > sizeof(tmp))
			break;
		table_api_lookup_result(req->id, req->s, tmp);
		break;
	case K_USERINFO:
		if (aldap_match_attr(m, q->attrs[0], &attr) == -1)
			break;
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[0]);
		if (strlcat(tmp, attr->str[0].ostr_val, sizeof(tmp)) > sizeof(tmp))
			break;
		if (strlcat(tmp, ":", sizeof(tmp)) > sizeof(tmp))
			break;
		aldap_free_attr(attr);
		if (aldap_match_attr(m, q->attrs[1], &attr) == -1)
			break;
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[1]);
		if (strlcat(tmp, attr->str[1].ostr_val, sizeof(tmp)) > sizeof(tmp))
			break;
		if (strlcat(tmp, ":", sizeof(tmp)) > sizeof(tmp))
			break;
		aldap_free_attr(attr);
		if (aldap_match_attr(m, q->attrs[2], &attr) == -1)
			break;
		if (attr->len > 1)
			log_warnx("req \"%s\" returned more then one attr \"%s\"", req->key, q->attrs[2]);
		if (strlcat(tmp, attr->str[1].ostr_val, sizeof(tmp)) > sizeof(tmp))
			break;
		table_api_lookup_result(req->id, req->s, tmp);
		break;
	default:
		log_warnx("unhandled service");
		break;
	}

	aldap_free_attr(attr);
}

static void
ldap_handle_response(const char *ldapid, const struct aldap_message *m, struct request *req)
{
	switch (req->o) {
	case O_CHECK:
		switch (m->message_type) {
		case LDAP_RES_SEARCH_ENTRY:
			table_api_check_result(req->id, true);
			break;
		case LDAP_RES_SEARCH_RESULT:
			table_api_check_result(req->id, false);
			break;
		default:
			table_api_error(req->id, req->o, "unknown ldap response");
			break;
		}
		dict_pop(&requests, ldapid);
		table_api_free_request(req);
		break;
	case O_LOOKUP:
		switch (m->message_type) {
		case LDAP_RES_SEARCH_ENTRY:
			ldap_lookup_entry(req, m);
			break;
		case LDAP_RES_SEARCH_RESULT:
			if (m->page && m->page->cookie_len) {
				table_api_error(req->id, req->o, "paginagion not yet implemented");
			} else {
				table_api_lookup_finish(req->id);
			}
			dict_pop(&requests, ldapid);
			table_api_free_request(req);
			break;
		default:
			table_api_error(req->id, req->o, "unknown ldap response");
			dict_pop(&requests, ldapid);
			table_api_free_request(req);
			break;
		}
	default:
		table_api_error(req->id, req->o, NULL);
		dict_pop(&requests, ldapid);
		table_api_free_request(req);
	}
}

static void
ldap_fd_callback(int fd, short revents)
{
	struct aldap_message	*m = NULL;
	struct request		*req;
	char			 ldapid[sizeof(int)*2+1];

	if (revents & POLLHUP || revents & POLLERR) {
		ldap_open();
		return;
	}

	do {
		aldap_freemsg(m);
		m = aldap_parse(aldap, false);
		if (!m) {
			switch (aldap->err) {
			case ALDAP_ERR_NEED_POLLOUT:
				table_api_fd_set_events(aldap->fd, POLLOUT);
				break;
			case ALDAP_ERR_NEED_POLLIN:
				table_api_fd_set_events(aldap->fd, POLLIN);
				break;
			default:
				ldap_open();
			}
			continue;
		}
		snprintf(ldapid, sizeof(ldapid), "%x", m->msgid);
		req = dict_get(&requests, ldapid);
		if (req)
			ldap_handle_response(ldapid, m, req);
	} while (m);
	aldap_freemsg(m);
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
	int			 oldfd = 0;

	if (aldap) {
		oldfd = aldap->fd;
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

	if ((amsg = aldap_parse(aldap, true)) == NULL) {
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

	if (!oldfd) {
		table_api_register_fd(aldap->fd, POLLIN, ldap_fd_callback);
	} else {
		table_api_replace_fd(oldfd, aldap->fd);
		table_api_fd_set_events(aldap->fd, POLLIN);
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

static struct query *
lookup_query(int type)
{
	struct query *q;
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
		return NULL;
	}
	return q;
}

static void
table_ldap_callback(struct request *req)
{
	struct aldap_filter_ctx ctx;
	char		  ldapid[sizeof(int)*2+1];
	int		  ret;
	struct query	 *q = lookup_query(req->s);
	char		 * const *attrs;
	int		  num;

	if (!q) {
		table_api_error(req->id, req->o, "service not configured");
		return;
	}

	switch (req->o) {
	case O_UPDATE:
		table_api_error(req->id, req->o, "update not implemented");
		table_api_free_request(req);
		return;
	case O_FETCH:
		table_api_error(req->id, req->o, "fetch not implemented");
		table_api_free_request(req);
		return;
	case O_CHECK:
		attrs = ldap_dn_attr;
		num = 1;
		break;
	case O_LOOKUP:
		attrs = q->attrs;
		num = 100;
		break;
	default:
		table_api_error(req->id, req->o, "unknown operation not implemented");
		table_api_free_request(req);
		return;
	}

	ctx.username = req->key;
	ctx.hostname = req->table;
	ret = aldap_search(aldap, basedn, LDAP_SCOPE_SUBTREE, q->filter, &ctx, attrs, false, num, 0, NULL);
	if (ret < 0) {
		table_api_error(req->id, req->o, NULL);
		ldap_open();
		return;
	}
	snprintf(ldapid, sizeof(ldapid), "%x", ret);
	dict_xset(&requests, ldapid, req);
}

int
main(int argc, char **argv)
{
	int ch;

	log_init(1);
	log_setverbose(~0);
	dict_init(&requests);

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

	table_api_on_request(table_ldap_callback);
	table_api_dispatch();

	return 0;
}
