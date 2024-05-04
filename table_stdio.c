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
#include <stdio.h>
#include <string.h>

#include "dict.h"
#include "table_stdio.h"

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
        case K_ALIAS:           return "alias";
        case K_DOMAIN:          return "domain";
        case K_CREDENTIALS:     return "credentials";
        case K_NETADDR:         return "netaddr";
        case K_USERINFO:        return "userinfo";
        case K_SOURCE:          return "source";
        case K_MAILADDR:        return "mailaddr";
        case K_ADDRNAME:        return "addrname";
        case K_MAILADDRMAP:     return "mailaddrmap";
	default:		return "???";
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
table_api_on_check(int(*cb)(int, struct dict *, const char *))
{
	handler_check = cb;
}

void
table_api_on_lookup(int(*cb)(int, struct dict  *, const char *, char *, size_t))
{
	handler_lookup = cb;
}

void
table_api_on_fetch(int(*cb)(int, struct dict *, char *, size_t))
{
	handler_fetch = cb;
}

const char *
table_api_get_name(void)
{
	return tablename;
}

int
table_api_dispatch(void)
{
	char		 buf[LINE_MAX];
	char		*t, *vers, *tname, *type, *service, *id, *key;
	char		*line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;
	int		 sid, r, configured = 0;

	dict_init(&params);

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
		strlcpy(tablename, tname, sizeof(tablename));

		type = t;
		if ((t = strchr(t, '|')) == NULL)
			errx(1, "malformed line: missing type");
		*t++ = '\0';

		if (!strcmp(type, "update")) {
			if (handler_update == NULL)
				errx(1, "no update handler registered");

			id = t;
			r = handler_update();
			printf("update-result|%s|%s\n", id,
			    r == -1 ? "error" : "ok");
			if (fflush(stdout) == EOF)
				err(1, "fflush");
			continue;
		}

		service = t;
		if ((t = strchr(t, '|')) == NULL)
			errx(1, "malformed line: missing service");
		*t++ = '\0';
		sid = service_id(service);

		id = t;

		r = -1;
		if (!strcmp(type, "fetch")) {
			if (handler_fetch == NULL)
				errx(1, "no fetch handler registered");

			if (registered_services & sid) {
				r = handler_fetch(sid, &params,
				    buf, sizeof(buf));
			}
			if (r == 1)
				printf("fetch-result|%s|found|%s\n", id, buf);
			else if (r == 0)
				printf("fetch-result|%s|not-found\n", id);
			else
				printf("fetch-result|%s|error\n", id);
			if (fflush(stdout) == EOF)
				err(1, "fflush");
			memset(buf, 0, sizeof(buf));
			continue;
		}

		if ((t = strchr(t, '|')) == NULL)
			errx(1, "malformed line: missing key");
		*t++ = '\0';
		key = t;

		if (!strcmp(type, "check")) {
			if (handler_check == NULL)
				errx(1, "no check handler registered");
			if (registered_services & sid) {
				r = handler_check(sid, &params, key);
			}
			if (r == 1)
				printf("check-result|%s|found\n", id);
			else if (r == 0)
				printf("check-result|%s|not-found\n", id);
			else
				printf("check-result|%s|error\n", id);
		} else if (!strcmp(type, "lookup")) {
			if (handler_lookup == NULL)
				errx(1, "no lookup handler registered");
			if (registered_services & sid) {
				r = handler_lookup(sid, &params, key,
				    buf, sizeof(buf));
			}
			if (r == 1)
				printf("lookup-result|%s|found|%s\n", id, buf);
			else if (r == 0)
				printf("lookup-result|%s|not-found\n", id);
			else
				printf("lookup-result|%s|error\n", id);
			memset(buf, 0, sizeof(buf));
		} else
			errx(1, "unknown action %s", type);

		if (fflush(stdout) == EOF)
			err(1, "fflush");
	}

	if (ferror(stdin))
		err(1, "getline");

	return (0);
}
