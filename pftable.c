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

#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "pfresolved.h"

int
pftable_set_addresses(struct pfresolved *env, struct pfresolved_table *table)
{
	struct pfioc_table		 io;
	struct pfresolved_table_entry	*entry;
	struct pfr_addr			*buffer = NULL;
	int				 count = 0, res;

	bzero(&io, sizeof(io));

	if (strlcpy(io.pfrio_table.pfrt_name, table->pft_name,
	    sizeof(io.pfrio_table.pfrt_name)) >=
	    sizeof(io.pfrio_table.pfrt_name)) {
		log_errorx("%s: table name is too long", __func__);
		return (-1);
	}

	RB_FOREACH(entry, pfresolved_table_entries, &table->pft_entries) {
		if ((buffer = recallocarray(buffer, count, count + 1,
		    sizeof(*buffer))) == NULL)
			fatal("%s: recallocarray", __func__);

		buffer[count].pfra_af = entry->pfte_addr.pfa_af;
		if (entry->pfte_addr.pfa_af == AF_INET) {
			buffer[count].pfra_ip4addr = entry->pfte_addr.pfa_addr.in4;
		} else {
			buffer[count].pfra_ip6addr = entry->pfte_addr.pfa_addr.in6;
		}
		buffer[count].pfra_net = entry->pfte_addr.pfa_prefixlen;
		buffer[count].pfra_not = entry->pfte_negate;
		count++;
	}

	io.pfrio_buffer = buffer;
	io.pfrio_size = count;
	io.pfrio_esize = sizeof(*buffer);

	log_info("%s: updating addresses for pf table: %s", __func__,
	    table->pft_name);

	res = ioctl(env->sc_pf_device, DIOCRSETADDRS, &io);
	if (res == -1 && errno == ESRCH) {
		log_notice("%s: pf table %s does not exist, creating it",
		    __func__, table->pft_name);
		if (pftable_create_table(env, table->pft_name) == -1) {
			log_errorx("%s: failed to create pf table %s", __func__,
			    table->pft_name);
			return (-1);
		}
		res = ioctl(env->sc_pf_device, DIOCRSETADDRS, &io);
	}

	if (res == -1) {
		log_warn("%s: failed to update addresses for pf table %s",
		    __func__, table->pft_name);
	} else {
		log_debug("%s: updated addresses for pf table %s: "
		    "added: %d, deleted: %d, changed: %d",
		    __func__, table->pft_name, io.pfrio_nadd, io.pfrio_ndel,
		    io.pfrio_nchange);
	}

	free(buffer);

	return (res);
}

int
pftable_clear_addresses(struct pfresolved *env, const char *table_name)
{
	struct pfioc_table		 io;
	int				 res;

	bzero(&io, sizeof(io));

	if (strlcpy(io.pfrio_table.pfrt_name, table_name,
	    sizeof(io.pfrio_table.pfrt_name)) >=
	    sizeof(io.pfrio_table.pfrt_name)) {
		log_errorx("%s: table name is too long", __func__);
		return (-1);
	}

	log_info("%s: clearing addresses for pf table %s", __func__,
	    table_name);
	res = ioctl(env->sc_pf_device, DIOCRCLRADDRS, &io);
	if (res == -1) {
		log_warn("%s: failed to clear addresses for pf table %s",
		    __func__, table_name);
	} else {
		log_debug("%s: cleared addresses for pf table %s: removed: %d",
		    __func__, table_name, io.pfrio_ndel);
	}

	return (res);
}

int
pftable_create_table(struct pfresolved *env, const char *table_name)
{
	struct pfioc_table               io;
	struct pfr_table                 table;
	int                              res;

	bzero(&io, sizeof(io));
	bzero(&table, sizeof(table));

	if (strlcpy(table.pfrt_name, table_name, sizeof(table.pfrt_name)) >=
	    sizeof(table.pfrt_name)) {
		log_errorx("%s: table name is too long", __func__);
		return (-1);
	}

	io.pfrio_buffer = &table;
	io.pfrio_size = 1;
	io.pfrio_esize = sizeof(table);

	log_info("%s: creating pf table %s", __func__, table_name);

	res = ioctl(env->sc_pf_device, DIOCRADDTABLES, &io);

	if (res == 0 && io.pfrio_nadd == 0)
		log_debug("%s: table already exists", __func__);

	return (res);
}
