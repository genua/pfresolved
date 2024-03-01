/*
 * Copyright (c) 2024 genua GmbH
 * Copyright (c) 2007-2013 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003 Henning Brauer <henning@openbsd.org>
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

#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include "pfresolved.h"
#include "parser.h"

__dead void	usage(void);

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-s socket] command [arg ...]\n", __progname);

	exit(1);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un	 s_un;
	struct parse_result	*res;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	int             	 c;
	int			 ctl_sock;
	int			 done = 1;
	int			 n;
	const char      	*sock = PFRESOLVED_SOCKET;

	while ((c = getopt(argc, argv, "s:")) != -1) {
		switch (c) {
		case 's':
			sock = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if ((res = parse(argc, argv)) == NULL)
		exit(1);

	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "%s: socket", __func__);

	bzero(&s_un, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	if (strlcpy(s_un.sun_path, sock,
	    sizeof(s_un.sun_path)) >= sizeof(s_un.sun_path))
		err(1, "%s: %s name too long", __func__, sock);

	if (connect(ctl_sock, (struct sockaddr *)&s_un, sizeof(s_un)) == -1)
		err(1, "%s: connect", __func__);

	if (pledge("stdio", NULL) == -1)
		err(1, "%s: pledge", __func__);

	if ((ibuf = calloc(1, sizeof(*ibuf))) == NULL)
		err(1, "%s: calloc", __func__);

	imsg_init(ibuf, ctl_sock);

	switch (res->action) {
	case NONE:
		usage();
		/* NOTREACHED */
		break;
	case LOG:
		imsg_compose(ibuf, IMSG_CTL_VERBOSE, 0, 0, -1, &res->value,
		    sizeof(res->value));
		printf("loglevel request sent.\n");
		break;
	case RELOAD:
		imsg_compose(ibuf, IMSG_CTL_RELOAD, 0, 0, -1, NULL, 0);
		printf("reload request sent.\n");
		break;
	case HINTS:
		imsg_compose(ibuf, IMSG_CTL_HINTS, 0, 0, -1, NULL, 0);
		printf("hints file request sent.\n");
		break;
	}

	while (ibuf->w.queued) {
		if (msgbuf_write(&ibuf->w) <= 0 && errno != EAGAIN)
			err(1, "%s: msgbuf_write", __func__);
	}

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			errx(1, "%s: imsg_read error", __func__);
		if (n == 0)
			errx(1, "%s: pipe closed", __func__);

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "%s: imsg_get error", __func__);
			if (n == 0)
				break;

			switch (res->action) {
			default:
				break;
			}

			imsg_free(&imsg);
		}
	}

	close(ctl_sock);
	free(ibuf);

	return (0);
}
