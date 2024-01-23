/*
 * Copyright (c) 2023 genua GmbH
 * All rights reserved.
 */

/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2004, 2005 Hans-Joerg Hoexer <hshoexer@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pfresolved.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

static struct pfresolved	*env = NULL;
static struct pfresolved_table	*cur_table = NULL;

int				 add_table_value(struct pfresolved_table *,
				     const char *);
int				 add_static_address(struct pfresolved_table *,
				     const char *, int);
int				 add_host(struct pfresolved_table *,
				     const char *);
struct pfresolved_table		*table_lookup_or_create(const char *);
void				 applymask4(struct in_addr *, int);
void				 applymask6(struct in6_addr *, int);
void				 in6_prefixlen2mask(struct in6_addr *, int);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token  ERROR
%token	INCLUDE
%token	<v.string>		STRING
%token	<v.number>		NUMBER
%type	<v.string>		string
%type	<v.string>		table_name
%type	<v.string>		table_value

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar include '\n'
		| grammar table_def '\n'
		| grammar varset '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

table_def	: table_begin optnl table_values optnl table_end
		;

table_begin	: table_name '{'
		{
			if ((cur_table = table_lookup_or_create($1)) == NULL) {
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

table_end	: '}'
		{
			cur_table = NULL;
		}
		;

table_values	: /* empty */
		| table_values include optcomma optnl
		| table_values table_value optcomma optnl
		{
			if (add_table_value(cur_table, $2) == -1) {
				yyerror("add_table_value failed");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| table_values '!' table_value optcomma optnl
		{
			if (add_static_address(cur_table, $3, 1) == -1) {
				yyerror("add_static_address failed");
				free($3);
				YYERROR;
			}
			free($3);
		}
		;

table_name	: STRING
		{
			if (strlen($1) >= PF_TABLE_NAME_SIZE) {
				yyerror("table name too long, max %d chars",
				PF_TABLE_NAME_SIZE - 1);
				YYERROR;
			}
			$$ = $1;
		}
		;

table_value	: STRING
		| STRING '/' NUMBER
		{
			if ((asprintf(&$$, "%s/%lld", $1, $3)) == -1)
				err(1, "string: asprintf");

			free($1);
		}
		;

string		: string STRING
		{
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				err(1, "string: asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string
		{
			char *s = $1;
			log_debug("%s = \"%s\"\n", $1, $3);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				err(1, "cannot store variable");
			free($1);
			free($3);
		}
		;

optnl		: /* empty */
		| '\n' optnl
		;

optcomma	: /* empty */
		| ','
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s: %d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "include", INCLUDE }
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		return (p->k_val);
	} else {
		return (STRING);
	}
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "%s", __func__);
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		warn("%s", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		warn("%s", __func__);
		free(nfile);
		return (NULL);
	}
	if (TAILQ_FIRST(&files) == NULL && strcmp(nfile->name, "-") == 0) {
		nfile->stream = stdin;
		free(nfile->name);
		if ((nfile->name = strdup("stdin")) == NULL) {
			warn("%s", __func__);
			free(nfile);
			return (NULL);
		}
	} else if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		warn("%s", __func__);
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;

	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, struct pfresolved *x_env)
{
	struct sym	*sym;
	int		 errors = 0;

	env = x_env;
	cur_table = NULL;

	if ((file = pushfile(filename, 0)) == NULL)
		return (-1);
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	while ((sym = TAILQ_FIRST(&symhead))) {
		if (!sym->used)
			log_debug("warning: macro '%s' not "
			    "used\n", sym->nam);
		free(sym->nam);
		free(sym->val);
		TAILQ_REMOVE(&symhead, sym, entry);
		free(sym);
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	sym = strndup(s, val - s);
	if (sym == NULL)
		err(1, "%s", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

int
add_table_value(struct pfresolved_table *table, const char *value)
{
	if (!table)
		return (-1);

	if (add_static_address(table, value, 0) == -1 &&
	    add_host(table, value) == -1)
		return (-1);

	return (0);
}

int
add_static_address(struct pfresolved_table *table, const char *value, int negate)
{
	struct pfresolved_table_entry	*entry, *old;
	struct in_addr			 in4;
	struct in6_addr			 in6;
	int				 bits;

	bzero(&in4, sizeof(in4));
	bzero(&in6, sizeof(in6));

	if ((entry = calloc(1, sizeof(*entry))) == NULL)
		fatal("%s: calloc", __func__);

	if ((bits = inet_net_pton(AF_INET, value, &in4, sizeof(in4))) != -1) {
		if (negate && bits != 32) {
			yyerror("negation is not allowed for networks");
			free(entry);
			return (-1);
		}
		applymask4(&in4, bits);
		entry->pfte_addr.pfa_af = AF_INET;
		entry->pfte_addr.pfa_addr.in4 = in4;
		entry->pfte_addr.pfa_prefixlen = bits;
	} else if ((bits = inet_net_pton(AF_INET6, value, &in6,
	    sizeof(in6))) != -1) {
		if (negate && bits != 128) {
			yyerror("negation is not allowed for networks");
			free(entry);
			return (-1);
		}
		applymask6(&in6, bits);
		entry->pfte_addr.pfa_af = AF_INET6;
		entry->pfte_addr.pfa_addr.in6 = in6;
		entry->pfte_addr.pfa_prefixlen = bits;
	} else {
		free(entry);
		return (-1);
	}

	entry->pfte_static = 1;
	entry->pfte_negate = negate;

	old = RB_INSERT(pfresolved_table_entries, &table->pft_entries, entry);
	if (old) {
		free(entry);
		if (old->pfte_negate != negate) {
			yyerror("the same address cannot be specified in normal"
			    " and negated form");
			return (-1);
		} else {
			log_warn("duplicate entry in config: %s %s",
			    table->pft_name, value);
		}
	}
	return (0);
}

int
add_host(struct pfresolved_table *table, const char *value)
{
	struct pfresolved_host		*host, *old_host;
	struct pfresolved_table_ref	*ref, *old_ref;

	if (strlen(value) == 0) {
		yyerror("hostname is empty");
		return (-1);
	}

	if ((host = calloc(1, sizeof(*host))) == NULL)
		fatal("%s: calloc", __func__);

	RB_INIT(&host->pfh_tables);

	if (strlcpy(host->pfh_hostname, value, sizeof(host->pfh_hostname))
	    >= sizeof(host->pfh_hostname)) {
		yyerror("hostname is too long");
		free(host);
		return (-1);
	}

	if ((ref = calloc(1, sizeof(*ref))) == NULL)
		fatal("%s: calloc", __func__);

	ref->pftr_table = table;
	RB_INSERT(pfresolved_table_refs, &host->pfh_tables, ref);

	old_host = RB_INSERT(pfresolved_hosts, &env->sc_hosts, host);
	if (old_host) {
		old_ref = RB_INSERT(pfresolved_table_refs,
		    &old_host->pfh_tables, ref);
		if (old_ref) {
			log_warn("duplicate entry in config: %s %s",
			    table->pft_name, value);
			free(ref);
		}
		free(host);
	}

	return (0);
}

struct pfresolved_table *
table_lookup_or_create(const char *table_name)
{
	struct pfresolved_table		*table, *old;

	if ((table = calloc(1, sizeof(*table))) == NULL)
		fatal("%s: calloc", __func__);

	RB_INIT(&table->pft_entries);

	if (strlcpy(table->pft_name, table_name, sizeof(table->pft_name))
	    >= sizeof(table->pft_name)) {
		yyerror("table name is too long");
		free(table);
		return (NULL);
	}

	old = RB_INSERT(pfresolved_tables, &env->sc_tables, table);
	if (old) {
		free(table);
		return (old);
	}

	return (table);
}

void applymask4(struct in_addr *addr, int prefixlen)
{
	uint32_t	 mask = 0;

	if (prefixlen == 0)
		return;

	if (prefixlen < 0 || prefixlen > 32)
		fatalx("%s: invalid prefixlen: %d", __func__, prefixlen);

	mask = htonl(0xffffffff << (32 - prefixlen));

	addr->s_addr = addr->s_addr & mask;
}

void applymask6(struct in6_addr *addr, int prefixlen)
{
	struct in6_addr		 mask;

	if (prefixlen == 0)
		return;

	in6_prefixlen2mask(&mask, prefixlen);

	for (int i = 0; i < 16; i++) {
		addr->s6_addr[i] = addr->s6_addr[i] & mask.s6_addr[i];
	}
}

/* from sys/netinet6/in.c */
void
in6_prefixlen2mask(struct in6_addr *maskp, int len)
{
	u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (0 > len || len > 128) {
		fatalx("%s: invalid prefixlen: %d", __func__, len);
	}

	bzero(maskp, sizeof(*maskp));
	bytelen = len / 8;
	bitlen = len % 8;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	/* len == 128 is ok because bitlen == 0 then */
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}
