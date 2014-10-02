/**
 * ssltrace -  hook SSL libraries to record keying data of SSL connections
 * Copyright (C) 2013  Jethro G. Beekman
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "ssltrace.h"

#include <openssl/ssl.h>

static void capture_session(int read, SSL *s, const void *buf, size_t len)
{
	int fd;
	if (read)
		fd = SSL_get_rfd(s);
	else
		fd = SSL_get_wfd(s);
	uint64_t entropy[2] = {fd, (uint64_t)s};
	if (fd < 0) {
		if (read)
			entropy[0] = (uint64_t)SSL_get_rbio(s);
		else
			entropy[0] = (uint64_t)SSL_get_wbio(s);
	}
	ssltrace_capture_payload(read, entropy, (const char *)buf, len);
}

WRAP(int,SSL_read,(SSL *s, void *buf, int num))
{
	WRAPINIT(SSL_read);

	int ret = _SSL_read(s, buf, num);

	if (ret > 0)
		capture_session(1, s, buf, ret);

	return ret;
}

WRAP(int,SSL_write,(SSL *s, const void *buf, int num))
{
	WRAPINIT(SSL_write);

	int ret = _SSL_write(s, buf, num);

	if (ret > 0)
		capture_session(0, s, buf, ret);

	return ret;
}
