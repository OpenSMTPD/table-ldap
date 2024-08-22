/*	$OpenBSD$	*/

/*
 * Copyright (c) Philipp Takacs <philipp@bureaucracy.de>
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/buffer_compat.h>

#include "dict.h"
#include "log.h"
#include "table_api.h"

#ifndef MAXFDS
#define MAXFDS 16
#endif

static void (*handler_async)(struct request *);
static int (*handler_update)(void);
static int (*handler_check)(int, struct dict *, const char *);
static int (*handler_lookup)(int, struct dict *, const char *, char *, size_t);
static int (*handler_fetch)(int, struct dict *, char *, size_t);

static nfds_t		 nfds;
static struct pollfd	 fds[MAXFDS];
static fd_callback	 cbs[MAXFDS];

static struct evbuffer	*inbuffer;

static bool		 configured;

static char		 tablename[128];

/*
 * backword compatibility:
 * register all the services since we don't have a clue yet what the
 * table will do
 */
static int		 registered_services = K_ANY;

/* Dummy; just kept for backward compatibility */
static struct dict	 params;
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
		table_api_error(id, O_UPDATE, NULL);
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
		table_api_error(id, O_CHECK, NULL);
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
		table_api_lookup_result(id, service, buf);
	}
	if (r == 1 || r == 0)
		table_api_lookup_finish(id);
	else
		table_api_error(id, O_LOOKUP, NULL);
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
		table_api_error(id, O_FETCH, NULL);
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

void
table_api_on_request(void(*cb)(struct request *))
{
	handler_async = cb;
}

const char *
table_api_get_name(void)
{
	return tablename;
}

void
table_api_error(const char *id, enum table_operation o, const char *error)
{
	struct evbuffer	*res;

	switch(o) {
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
	if (error && *error) {
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
	res = dict_pop(&lookup_entries, id);
	if (res)
		evbuffer_free(res);
}

void
table_api_update_finish(const char *id)
{
	if (!id) {
		log_warnx("%s: unknow id %s", __func__, id);
		return;
	}

	printf("update-result|%s|ok\n", id);
	if (fflush(stdout) == EOF)
		err(1, "fflush");
}

void
table_api_check_result(const char *id, bool found)
{
	if (found)
		printf("check-result|%s|found\n", id);
	else
		printf("check-result|%s|not-found\n", id);

	if (fflush(stdout) == EOF)
		err(1, "fflush");
}

void
table_api_lookup_result(const char *id, enum table_service s, const char *buf)
{
	const char alias_sep[] = ", ";
	struct evbuffer *res;

	res = dict_get(&lookup_entries, id);

	if (!res) {
		res = evbuffer_new();
		if (!res) {
			table_api_error(id, O_LOOKUP, "can not alloc result");
			return;
		}
		if (evbuffer_add(res, buf, strlen(buf)) == -1) {
			table_api_error(id, O_LOOKUP, "can not alloc result");
			evbuffer_free(res);
			return;
		}
		dict_set(&lookup_entries, id, res);
		return;
	}
	switch(s) {
	case K_ALIAS:
		if (evbuffer_add(res, alias_sep, sizeof(alias_sep)-1) == -1) {
			table_api_error(id, O_LOOKUP, "can not extend result");
			dict_pop(&lookup_entries, id);
			evbuffer_free(res);
			return;
		}
		if (evbuffer_add(res, buf, 0) == -1) {
			table_api_error(id, O_LOOKUP, "can not extend result");
			dict_pop(&lookup_entries, id);
			evbuffer_free(res);
			return;
		}
		break;
	default:
		log_warnx("id: %s lookup result override", id);
		evbuffer_drain(res, evbuffer_get_length(res));
		if (evbuffer_add(res, buf, sizeof(buf)) == -1) {
			table_api_error(id, O_LOOKUP, "can not alloc result");
			dict_pop(&lookup_entries, id);
			evbuffer_free(res);
			return;
		}
	}
}

void
table_api_lookup_finish(const char *id)
{
	struct evbuffer	*res;

	res = dict_pop(&lookup_entries, id);
	if (res && evbuffer_get_length(res)) {
		if (evbuffer_add(res, "\0", 1) == -1) {
			table_api_error(id, O_LOOKUP, "can not extend result");
			evbuffer_free(res);
			return;
		}
		printf("lookup-result|%s|found|%s\n", id, evbuffer_pullup(res, -1));
	} else {
		printf("lookup-result|%s|not-found\n", id);
	}

	if (fflush(stdout) == EOF)
		err(1, "fflush");
	if (res)
		evbuffer_free(res);
}

void
table_api_fetch_result(const char *id, const char *buf)
{
	if (buf && *buf)
		printf("fetch-result|%s|found|%s\n", id, buf);
	else
		printf("fetch-result|%s|not-found\n", id);

	if (fflush(stdout) == EOF)
		err(1, "fflush");
}

void
table_api_register_fd(int fd, short events, fd_callback cb)
{
	/* first fd is reservated for stdin */
	if (!nfds)
		nfds++;

	if (nfds >= MAXFDS)
		exit(1);

	fds[nfds].fd = fd;
	fds[nfds].events = events;
	cbs[nfds] = cb;
	nfds++;
}

void
table_api_replace_fd(int old, int new)
{
	for (nfds_t i = 1; i < nfds; i++) {
		if (fds[i].fd != old) {
			continue;
		}
		fds[i].fd = new;
	}
}

void
table_api_fd_set_events(int fd, short events)
{
	for (size_t i = 0; i < nfds; i++) {
		if (fds[i].fd != fd)
			continue;
		fds[i].events = events;
		return;
	}
}

void
table_api_remove_fd(int fd)
{
	for (nfds_t i = 1; i < nfds; i++) {
		if (fds[i].fd != fd) {
			continue;
		}
		nfds--;
		if (i+1 > nfds) {
			break;
		}
		memmove(fds+i, fds+i+1, (nfds-i)*sizeof(*fds));
		memmove(cbs+i, cbs+i+1, (nfds-i)*sizeof(*cbs));
	}
}

bool
table_api_parse_line(char *line, size_t linelen, struct request *req)
{
	char		*t, *vers, *tname, *type, *service, *id, *key;
	int		 sid;

	t = line;
	(void) linelen;

	if (strncmp(t, "table|", 6)) {
		log_warnx("malformed line");
		return false;
	}
	t += 6;

	vers = t;
	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing version");
		return false;
	}
	*t++ = '\0';

	if (strcmp(vers, "0.1") != 0) {
		log_warnx("unsupported protocol version: %s", vers);
		return false;
	}

	/* skip timestamp */
	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing timestamp");
		return false;
	}
	*t++ = '\0';

	tname = t;
	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing table name");
		return false;
	}
	*t++ = '\0';
	if (t - tname - 1 > (ptrdiff_t)req->tablesize) {
		req->table = realloc(req->table, t - tname - 1);
		req->tablesize = t - tname - 1;
		if (!req->table)
			fatal("realloc");
	}
	memcpy(req->table, tname, req->tablesize);

	type = t;
	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing type");
		return false;
	}
	*t++ = '\0';

	if (!strcmp(type, "update")) {
		if (line + linelen - t > (ptrdiff_t)req->idsize) {
			req->id = realloc(req->id, line + linelen - t);
			req->idsize = line + linelen - t;
			if (!req->id)
				fatal("realloc");
		}
		memcpy(req->id, t, line + linelen - t);
		req->o = O_UPDATE;
		return true;
	}

	service = t;
	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing service");
		return false;
	}
	*t++ = '\0';
	sid = service_id(service);

	id = t;

	if (!strcmp(type, "fetch")) {
		if (line + linelen - id > (ptrdiff_t)req->idsize) {
			req->id = realloc(req->id, line + linelen - id);
			req->idsize = line + linelen - id;
			if (!req->id)
				fatal("realloc");
		}
		memcpy(req->id, id, line + linelen - id);
		req->o = O_FETCH;
		req->s = sid;
		req->key = NULL;
		return true;
	}

	if ((t = strchr(t, '|')) == NULL) {
		log_warnx("malformed line: missing key");
		return false;
	}
	*t++ = '\0';
	if (t - id - 1 > (ptrdiff_t)req->idsize) {
		req->id = realloc(req->id, t - id - 1);
		req->idsize = t - id - 1;
		if (!req->id)
			fatal("realloc");
	}
	memcpy(req->id, id, t - id - 1);

	key = t;
	if (line + linelen - key > (ptrdiff_t)req->keysize) {
		req->key = realloc(req->key, line + linelen - key);
		req->keysize = line + linelen - key;
		if (!req->key)
			fatal("realloc");
	}
	memcpy(req->key, key, line + linelen - key);

	if (!strcmp(type, "check")) {
		req->o = O_CHECK;
		req->s = sid;
		return true;
	} else if (!strcmp(type, "lookup")) {
		req->o = O_LOOKUP;
		req->s = sid;
		return true;
	} else {
		log_warnx("unknown action %s", type);
		return false;
	}
}

void
table_api_free_request(struct request *r)
{
	if (!r)
		return;

	free(r->id);
	free(r->table);
	free(r->key);
	free(r);
}

static void
do_callback(struct request *req)
{
	struct request *r;
	switch (req->o) {
	case O_UPDATE:
		if (handler_update) {
			fallback_update_handler(req->id, req->table);
			return;
		}
		break;
	case O_CHECK:
		if (handler_check) {
			fallback_check_handler(req->id, req->table, req->s, req->key);
			return;
		}
		break;
	case O_LOOKUP:
		if (handler_lookup) {
			fallback_lookup_handler(req->id, req->table, req->s, req->key);
			return;
		}
		break;
	case O_FETCH:
		if (handler_fetch) {
			fallback_fetch_handler(req->id, req->table, req->s);
			return;
		}
		break;
	default:
		break;
	}

	r = malloc(sizeof(*r));
	*r = *req;
	handler_async(r);
}

static void
api_callback(int fd, short revents)
{
	bool		 retry = true;
	char		 buf[BUFSIZ];
	size_t		 linelen;
	int		 serrno, ret;
	char		*line, *t;
	struct request	 req = {0};

	if (revents & (POLLERR|POLLNVAL)) {
		exit(1);
	}
	if (revents & POLLHUP) {
		exit(0);
	}

	do {
		ret = read(fd, buf, sizeof(buf));
		if (ret == 0) {
			/* EOF */
			exit(0);
		}
		if (ret < 0) {
			serrno = errno;
			if (serrno == EAGAIN || serrno == EWOULDBLOCK) {
				retry = false;
				continue;
			}
			err(1, "read");
		}
		evbuffer_add(inbuffer, buf, ret);
	} while (retry);

	while ((line = evbuffer_readline(inbuffer))) {
		linelen = strlen(line);
		t = line;
		if (configured) {
			if (!table_api_parse_line(line, linelen, &req)) {
				errx(1, "can not parse input line: %s", line);
			}
			do_callback(&req);
			free(line);
			continue;
		}

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
		}

		free(line);
	}
}

int
table_api_dispatch(void)
{
	int	 serrno, r;
	int flags;

	dict_init(&params);
	dict_init(&lookup_entries);

	inbuffer = evbuffer_new();

	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	cbs[0] = api_callback;
	if (!nfds)
		nfds++;

	while (nfds) {
		r = poll(fds, nfds, 1024);
		if (r == 0) {
			/* TODO implement some timeout handling */
			continue;
		}
		if (r < 0) {
			serrno = errno;
			if (serrno == ENOMEM || serrno == EAGAIN) {
				continue;
			}
		}

		for (nfds_t i = 0; i < nfds; i++) {
			if (fds[i].revents) {
				cbs[i](fds[i].fd, fds[i].revents);
			}
		}
	}

	return (0);
}
