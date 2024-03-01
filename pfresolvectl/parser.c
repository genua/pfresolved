/*
 * Copyright (c) 2024 genua GmbH
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "parser.h"

enum token_type {
	NOTOKEN,
	ENDTOKEN,
	KEYWORD,
	LOGLEVEL
};

struct token {
	enum token_type		 type;
	const char		*keyword;
	int			 value;
	const struct token	*next;
};

static const struct token t_main[];
static const struct token t_log[];

static const struct token t_main[] = {
	{ KEYWORD,	"log",		LOG,		t_log },
	{ KEYWORD,	"reload",	RELOAD,		NULL },
	{ KEYWORD,	"hints",	HINTS,		NULL },
	{ ENDTOKEN,	"",		NONE,		NULL }
};

static const struct token t_log[] = {
	{ LOGLEVEL,	"warn",     	0,	        NULL },
	{ LOGLEVEL,	"notice",     	1,	        NULL },
	{ LOGLEVEL,	"info",     	2,	        NULL },
	{ LOGLEVEL,	"debug",     	3,	        NULL },
	{ ENDTOKEN,	"",		NONE,		NULL }
};

static struct parse_result	 res;

const struct token		*match_token(char *, const struct token []);
void				 show_valid_args(const struct token []);

struct parse_result *
parse(int argc, char *argv[])
{
	const struct token	*table = t_main;
	const struct token	*match;

	bzero(&res, sizeof(res));

	while (argc >= 0) {
		if ((match = match_token(argv[0], table)) == NULL) {
			fprintf(stderr, "valid commands/args:\n");
			show_valid_args(table);
			return (NULL);
		}

		argc--;
		argv++;

		if (match->type == NOTOKEN || match->next == NULL)
			break;

		table = match->next;
	}

	if (argc > 0) {
		fprintf(stderr, "superfluous argument: %s\n", argv[0]);
		return (NULL);
	}

	return (&res);
}

const struct token *
match_token(char *word, const struct token table[])
{
	unsigned int		 i, match = 0;
	const struct token	*t = NULL;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			if (word == NULL || strlen(word) == 0) {
				match++;
				t = &table[i];
			}
			break;
		case KEYWORD:
			if (word != NULL && strncmp(word, table[i].keyword,
			    strlen(word)) == 0) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case LOGLEVEL:
			if (word != NULL && strncmp(word, table[i].keyword,
			    strlen(word)) == 0) {
				res.value = table[i].value;

				match++;
				t = &table[i];
			}
			break;
		case ENDTOKEN:
			break;
		}
	}

	if (match != 1) {
		if (word == NULL)
			fprintf(stderr, "missing argument:\n");
		else if (match > 1)
			fprintf(stderr, "ambiguous argument: %s\n", word);
		else if (match < 1)
			fprintf(stderr, "unknown argument: %s\n", word);
		return (NULL);
	}

	return (t);
}

void
show_valid_args(const struct token table[])
{
	int	i;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			fprintf(stderr, "  <cr>\n");
			break;
		case KEYWORD:
			fprintf(stderr, "  %s\n", table[i].keyword);
			break;
		case LOGLEVEL:
			fprintf(stderr, " %s\n", table[i].keyword);
			break;
		case ENDTOKEN:
			break;
		}
	}
}
