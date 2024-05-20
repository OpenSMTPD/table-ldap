/*	$OpenBSD$	*/

/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

#include "config.h"

#include <sys/tree.h>

#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <event.h>

#include "dict.h"
#include "log.h"
#include "table_stdio.h"

enum table_operation {
	O_UPDATE,
	O_CHECK,
	O_LOOKUP,
	O_FETCH,
};

struct request {
	enum	 table_operation o;
	char	*table;
	enum	 table_service s;
	char	*key;
};

static void (*handler_async_update)(const char *, const char *);
static void (*handler_async_check)(const char *, const char *, int, const char *);
static void (*handler_async_lookup)(const char *, const char *, int, const char *);
static void (*handler_async_fetch)(const char *, const char *, int);
static int (*handler_update)(void);
static int (*handler_check)(int, struct dict *, const char *);
static int (*handler_lookup)(int, struct dict *, const char *, char *, size_t);
static int (*handler_fetch)(int, struct dict *, char *, size_t);

static char		 tablename[128];

/*
 * backword compatibility:
 * register all the services since we don't have a clue yet what the
 * table will do
 */
static int		 registered_services = K_ANY;

/* Dummy; just kept for backward compatibility */
static struct dict	 params;
static struct dict	 requests;
static struct dict	 lookup_entries;

static int
service_id(const char *service)
{
	if (!strcmp(service, "alias"))
		return (K_ALIAS);
	if (!strcmp(service, "domain"))
		return (K_DOMAIN);
	if (!strcmp(service, "credentials"))
		return (K_CREDENTIALS);
	if (!strcmp(service, "netaddr"))
		return (K_NETADDR);
	if (!strcmp(service, "userinfo"))
		return (K_USERINFO);
	if (!strcmp(service, "source"))
		return (K_SOURCE);
	if (!strcmp(service, "mailaddr"))
		return (K_MAILADDR);
	if (!strcmp(service, "addrname"))
		return (K_ADDRNAME);
	if (!strcmp(service, "mailaddrmap"))
		return (K_MAILADDRMAP);

	errx(1, "unknown service %s", service);
}

static char *
table_api_service_name(enum table_service s)
{
	switch (s) {
	case K_ALIAS:		return "alias";
	case K_DOMAIN:		return "domain";
	case K_CREDENTIALS:	return "credentials";
	case K_NETADDR:		return "netaddr";
	case K_USERINFO:	return "userinfo";
	case K_SOURCE:		return "source";
	case K_MAILADDR:	return "mailaddr";
	case K_ADDRNAME:	return "addrname";
	case K_MAILADDRMAP:	return "mailaddrmap";
	default:		return "???";
	}
}

static void
fallback_update_handler(const char *id, const char *tname)
{
	int r;
	strlcpy(tablename, tname, sizeof(tablename));

	if (handler_update == NULL)
		errx(1, "no update handler registered");

	r = handler_update();
	if (r == 1)
		table_api_update_finish(id);
	else
		table_api_error(id, NULL);
}

static void
fallback_check_handler(const char *id, const char *tname, int service, const char *key)
{
	int r;
	strlcpy(tablename, tname, sizeof(tablename));

	if (handler_check == NULL)
		errx(1, "no check handler registered");

	r = handler_check(service, &params, key);
	if (r == 0 || r == 1)
		table_api_check_result(id, r == 1);
	else
		table_api_error(id, NULL);
}

static void
fallback_lookup_handler(const char *id, const char *tname, int service, const char *key)
{
	char buf[LINE_MAX];
	int r;
	strlcpy(tablename, tname, sizeof(tablename));

	if (handler_lookup == NULL)
		errx(1, "no lookup handler registered");

	r = handler_lookup(service, &params, key, buf, sizeof(buf));
	if (r == 1) {
		table_api_lookup_result(id, buf);
	}
	if (r == 1 || r == 0)
		table_api_lookup_finish(id);
	else
		table_api_error(id, NULL);
}

static void
fallback_fetch_handler(const char *id, const char *tname, int service)
{
	char buf[LINE_MAX];
	int r;
	strlcpy(tablename, tname, sizeof(tablename));

	if (handler_fetch == NULL)
		errx(1, "no fetch handler registered");

	r = handler_fetch(service, &params, buf, sizeof(buf));
	switch(r) {
	case 1:
		table_api_fetch_result(id, buf);
		break;
	case 0:
		table_api_fetch_result(id, NULL);
		break;
	default:
		table_api_error(id, NULL);
	}
}

void
table_api_register_services(int s)
{
	registered_services = K_ANY & s;
}

void
table_api_on_update(int(*cb)(void))
{
	handler_update = cb;
}

void
table_api_on_update_async(void(*cb)(const char *, const char *))
{
	handler_async_update = cb;
}

void
table_api_on_check(int(*cb)(int, struct dict *, const char *))
{
	handler_check = cb;
}

void
table_api_on_check_async(void(*cb)(const char *, const char *, int, const char *))
{
	handler_async_check = cb;
}

void
table_api_on_lookup(int(*cb)(int, struct dict  *, const char *, char *, size_t))
{
	handler_lookup = cb;
}

void
table_api_on_lookup_async(void(*cb)(const char *, const char *, int, const char *))
{
	handler_async_lookup = cb;
}

void
table_api_on_fetch(int(*cb)(int, struct dict *, char *, size_t))
{
	handler_fetch = cb;
}

void
table_api_on_fetch_async(void(*cb)(const char *, const char *, int))
{
	handler_async_fetch = cb;
}

const char *
table_api_get_name(void)
{
	return tablename;
}

void

table_api_error(const char *id, const char *error)
{
	struct request  *req;
	struct evbuffer	*res;

	req = dict_pop(&requests, id);

	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	switch(req->o) {
	case O_UPDATE:
		printf("update-result|%s|error", id);
		break;
	case O_CHECK:
		printf("check-result|%s|error", id);
		break;
	case O_LOOKUP:
		printf("lookup-result|%s|error", id);
		break;
	case O_FETCH:
		printf("fetch-result|%s|error", id);
		break;
	}

#ifdef errormassage
	if (error) {
		printf("|%s\n", error);
	} else {
		puts("|unknown");
	}
#else
	(void)error;
	puts("");
#endif
	if (fflush(stdout) == EOF)
		err(1, "fflush");
	free(req);
	res = dict_pop(&lookup_entries, id);
	if (res)
		evbuffer_free(res);
}

void
table_api_update_finish(const char *id)
{
	struct request	*req;

	req = dict_get(&requests, id);

	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	if (req->o != O_UPDATE) {
		table_api_error(id, NULL);
		return;
	}

	dict_pop(&requests, id);
	free(req->table);
	free(req);

	printf("update-result|%s|ok\n", id);
	if (fflush(stdout) == EOF)
		err(1, "fflush");
}

void
table_api_check_result(const char *id, bool found)
{
	struct request	*req;

	req = dict_get(&requests, id);

	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	if (req->o != O_CHECK) {
		table_api_error(id, NULL);
		return;
	}

	dict_pop(&requests, id);
	free(req->table);
	free(req->key);
	free(req);

	if (found)
		printf("check-result|%s|found\n", id);
	else
		printf("check-result|%s|not-found\n", id);

	if (fflush(stdout) == EOF)
		err(1, "fflush");
}

void
table_api_lookup_result(const char *id, const char *buf)
{
	const char alias_sep[] = ", ";
	struct request	*req;
	struct evbuffer *res;

	req = dict_get(&requests, id);

	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	if (req->o != O_LOOKUP) {
		table_api_error(id, NULL);
		return;
	}

	res = dict_get(&lookup_entries, id);

	if (!res) {
		res = evbuffer_new();
		if (!res) {
			table_api_error(id, "can not alloc result");
			return;
		}
		if (evbuffer_add(res, buf, strlen(buf)) == -1) {
			table_api_error(id, "can not alloc result");
			return;
		}
		dict_set(&lookup_entries, id, res);
		return;
	}
	switch(req->s) {
	case K_ALIAS:
		if (evbuffer_add(res, alias_sep, sizeof(alias_sep)-1) == -1) {
			table_api_error(id, "can not extend result");
			return;
		}
		if (evbuffer_add(res, buf, 0) == -1) {
			table_api_error(id, "can not extend result");
			return;
		}
		break;
	default:
		log_warnx("id: %s lookup result override", id);
		evbuffer_drain(res, evbuffer_get_length(res));
		if (evbuffer_add(res, buf, sizeof(buf)) == -1) {
			table_api_error(id, "can not alloc result");
			return;
		}
	}
}

void
table_api_lookup_finish(const char *id)
{
	struct request	*req;
	struct evbuffer	*res;

	req = dict_get(&requests, id);
	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}
	if (req->o != O_LOOKUP) {
		table_api_error(id, NULL);
		return;
	}

	res = dict_get(&lookup_entries, id);
	if (res && evbuffer_get_length(res)) {
		if (evbuffer_add(res, "\0", 1) == -1) {
			table_api_error(id, "can not extend result");
			return;
		}
		printf("lookup-result|%s|found|%s\n", id, evbuffer_pullup(res, -1));
	} else {
		printf("lookup-result|%s|not-found\n", id);
	}

	if (fflush(stdout) == EOF)
		err(1, "fflush");
	dict_pop(&requests, id);
	free(req->table);
	free(req->key);
	free(req);
	res = dict_pop(&lookup_entries, id);
	if (res)
		evbuffer_free(res);
}

void
table_api_fetch_result(const char *id, const char *buf)
{
	struct request	*req;

	req = dict_get(&requests, id);

	if (!req) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	if (req->o != O_FETCH) {
		table_api_error(id, NULL);
		return;
	}

	if (buf && *buf)
		printf("fetch-result|%s|found|%s\n", id, buf);
	else
		printf("fetch-result|%s|not-found\n", id);

	if (fflush(stdout) == EOF)
		err(1, "fflush");
	dict_pop(&requests, id);
	free(req->table);
	free(req);
}

static void
handle_request(char *line, size_t linelen)
{
	char		*t, *vers, *tname, *type, *service, *id, *key;
	int		 sid;
	struct request	 *req = calloc(1, sizeof(*req));

	t = line;
	(void) linelen;

	if (strncmp(t, "table|", 6))
		errx(1, "malformed line");
	t += 6;

	vers = t;
	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing version");
	*t++ = '\0';

	if (strcmp(vers, "0.1") != 0)
		errx(1, "unsupported protocol version: %s", vers);

	/* skip timestamp */
	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing timestamp");
	*t++ = '\0';

	tname = t;
	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing table name");
	*t++ = '\0';
	req->table = strdup(tname);

	type = t;
	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing type");
	*t++ = '\0';

	if (!strcmp(type, "update")) {
		if (handler_async_update == NULL)
			errx(1, "no update handler registered");

		id = t;
		req->o = O_UPDATE;
		dict_set(&requests, id, req);

		handler_async_update(id, tname);
		return;
	}

	service = t;
	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing service");
	*t++ = '\0';
	sid = service_id(service);

	id = t;

	if (!strcmp(type, "fetch")) {
		if (handler_async_fetch == NULL)
			errx(1, "no fetch handler registered");

		if (!(registered_services & sid)) {
			printf("check-result|%s|error\n", id);
			if (fflush(stdout) == EOF)
				err(1, "fflush");
			return;
		}
		req->o = O_FETCH;
		req->s = sid;
		req->key = NULL;
		dict_set(&requests, id, req);
		handler_async_fetch(id, tname, sid);
		return;
	}

	if ((t = strchr(t, '|')) == NULL)
		errx(1, "malformed line: missing key");
	*t++ = '\0';
	key = t;

	if (!strcmp(type, "check")) {
		if (handler_async_check == NULL)
			errx(1, "no check handler registered");
		if (!(registered_services & sid)) {
			printf("check-result|%s|error\n", id);
			if (fflush(stdout) == EOF)
				err(1, "fflush");
			return;
		}
		req->o = O_CHECK;
		req->s = sid;
		req->key = strdup(key);
		dict_set(&requests, id, req);
		handler_async_check(id, tname, sid, key);
		return;
	} else if (!strcmp(type, "lookup")) {
		if (handler_async_lookup == NULL)
			errx(1, "no lookup handler registered");
		if (!(registered_services & sid)) {
			printf("lookup-result|%s|error\n", id);
			if (fflush(stdout) == EOF)
				err(1, "fflush");
			return;
		}
		req->o = O_LOOKUP;
		req->s = sid;
		req->key = strdup(key);
		dict_set(&requests, id, req);
		handler_async_lookup(id, tname, sid, key);
		return;
	} else
		errx(1, "unknown action %s", type);
}

int
table_api_dispatch(void)
{
	char		*t;
	char		*line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;
	int		 configured = 0;

	dict_init(&params);
	dict_init(&requests);
	dict_init(&lookup_entries);

	if (!handler_async_update)
		table_api_on_update_async(fallback_update_handler);
	if (!handler_async_check)
		table_api_on_check_async(fallback_check_handler);
	if (!handler_async_lookup)
		table_api_on_lookup_async(fallback_lookup_handler);
	if (!handler_async_fetch)
		table_api_on_fetch_async(fallback_fetch_handler);

	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';
		t = line;

		if (!configured) {
			if (strncmp(t, "config|", 7) != 0)
				errx(1, "unexpected config line: %s", line);
			t += 7;

			if (!strcmp(t, "ready")) {
				configured = 1;

				for (int s = K_ALIAS; s <= K_MAILADDRMAP; s <<= 1) {
					printf("register|%s\n", table_api_service_name(s));
				}

				puts("register|ready");
				if (fflush(stdout) == EOF)
					err(1, "fflush");
				continue;
			}

			continue;
		}

		handle_request(t, linelen);
	}

	if (ferror(stdin))
		err(1, "getline");

	return (0);
}
