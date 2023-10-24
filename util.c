/*
 * Copyright (c) 2023 genua GmbH
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

#include <arpa/inet.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pfresolved.h"

const char *
print_address(struct pfresolved_address *address)
{
	static char             buffer[64];

	if (address == NULL)
		return ("(NULL)");

	switch (address->pfa_af) {
	case AF_INET:
		inet_net_ntop(AF_INET, &address->pfa_addr.in4,
		    address->pfa_prefixlen, buffer, sizeof(buffer));
		break;
	case AF_INET6:
		inet_net_ntop(AF_INET6, &address->pfa_addr.in6,
		    address->pfa_prefixlen, buffer, sizeof(buffer));
		break;
	default:
		return ("(UNKNOWN AF)");
		break;
	}

	return (buffer);
}

int
address_cmp(const struct pfresolved_address *a,
    const struct pfresolved_address *b)
{
	int diff = 0;

	if (a == NULL && b == NULL)
		return (0);

	if (a == NULL)
		return (-1);

	if (b == NULL)
		return (1);

	if (!diff)
		diff = a->pfa_af - b->pfa_af;
	if (!diff)
		diff = memcmp(&a->pfa_addr, &b->pfa_addr,
		    sizeof(a->pfa_addr));
	if (!diff)
		diff = a->pfa_prefixlen - b->pfa_prefixlen;

	return (diff);
}

void
appendf(char **str, char *fmt, ...)
{
	va_list		 ap;
	char		*tmp, *new_str;

	va_start(ap, fmt);

	if (vasprintf(&tmp, fmt, ap) == -1)
		fatalx("%s: vasprintf", __func__);

	if (asprintf(&new_str, "%s%s", *str == NULL ? "" : *str, tmp) == -1)
		fatalx("%s: asprintf", __func__);

	free(tmp);
	free(*str);
	*str = new_str;

	va_end(ap);
}
