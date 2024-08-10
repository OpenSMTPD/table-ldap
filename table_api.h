/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2011 Gilles Chehade <gilles@poolp.org>
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

#if defined(__clang__) || defined(__GNUC__)
#define DEPRECATED __attribute__((deprecated))
#else
#define DEPRECATED
#endif

typedef void (*fd_callback)(int, short);

enum table_operation {
	O_UPDATE,
	O_CHECK,
	O_LOOKUP,
	O_FETCH,
};

enum table_service {
	K_ALIAS =	0x001,	/* returns struct expand	*/
	K_DOMAIN =	0x002,	/* returns struct destination	*/
	K_CREDENTIALS =	0x004,	/* returns struct credentials	*/
	K_NETADDR =	0x008,	/* returns struct netaddr	*/
	K_USERINFO =	0x010,	/* returns struct userinfo	*/
	K_SOURCE =	0x020,	/* returns struct source	*/
	K_MAILADDR =	0x040,	/* returns struct mailaddr	*/
	K_ADDRNAME =	0x080,	/* returns struct addrname	*/
	K_MAILADDRMAP =	0x100,	/* returns struct mailaddr	*/
	K_ANY =		0xfff,
};

struct request {
	char	*id;
	size_t	 idsize;
	enum	 table_operation o;
	char	*table;
	size_t	 tablesize;
	enum	 table_service s;
	char	*key;
	size_t	 keysize;
};

bool		 table_api_parse_line(char *line, size_t linelen, struct request *req);
void		 table_api_free_request(struct request *req);
void		 table_api_register_services(int);
void		 table_api_on_update(int(*)(void)) DEPRECATED;
void		 table_api_on_check(int(*)(int, struct dict *, const char *)) DEPRECATED;
void		 table_api_on_lookup(int(*)(int, struct dict *, const char *, char *, size_t)) DEPRECATED;
void		 table_api_on_fetch(int(*)(int, struct dict *, char *, size_t));
void		 table_api_on_request(void(*)(struct request *));
int		 table_api_dispatch(void);
void		 table_api_error(const char *, enum table_operation, const char *);
void		 table_api_update_finish(const char *);
void		 table_api_check_result(const char *, bool);
void		 table_api_lookup_result(const char *, enum table_service, const char *);
void		 table_api_lookup_finish(const char *);
void		 table_api_fetch_result(const char *, const char *);
const char	*table_api_get_name(void) DEPRECATED;
void		 table_api_register_fd(int fd, short events, fd_callback cb);
void		 table_api_replace_fd(int old, int new);
void		 table_api_remove_fd(int fd);
void		 table_api_fd_set_events(int fd, short events);
