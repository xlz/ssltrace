/**
 * ssltrace -  hook SSL libraries to record keying data of SSL connections
 * Copyright (C) 2013,2014  Jethro G. Beekman
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

#include <gnutls/gnutls.h>
#include <dlfcn.h>

static void capture_session(int read, gnutls_session_t s, const void *buf, size_t len)
{
	gnutls_transport_ptr_t p[2];
	gnutls_transport_get_ptr2(s, &p[0], &p[1]);
	uint64_t entropy[2] = {(uint64_t)p[!read], (uint64_t)s};
	ssltrace_capture_payload(read, entropy, (const char *)buf, len);
}

WRAP(ssize_t,gnutls_record_recv,(gnutls_session_t s, void *buf, size_t len))
{
	WRAPINIT(gnutls_record_recv);

	ssize_t ret = _gnutls_record_recv(s, buf, len);

	if (ret > 0)
		capture_session(1, s, buf, ret);

	return ret;
}

WRAP(ssize_t,gnutls_record_recv_seq,(gnutls_session_t s, void *buf, size_t len, unsigned char *seq))
{
	WRAPINIT(gnutls_record_recv);

	ssize_t ret = _gnutls_record_recv_seq(s, buf, len, seq);

	if (ret > 0)
		capture_session(1, s, buf, ret);

	return ret;
}

WRAP(ssize_t,gnutls_record_recv_packet,(gnutls_session_t s, gnutls_packet_t *p))
{
	WRAPINIT(gnutls_record_recv);

	ssize_t ret = _gnutls_record_recv_packet(s, p);

	if (ret > 0) {
		gnutls_datum_t buf;
		gnutls_packet_get(*p, &buf, NULL);
		if (buf.data && buf.size)
			capture_session(1, s, buf.data, ret);
	}

	return ret;
}

WRAP(ssize_t,gnutls_record_send,(gnutls_session_t s, const void *buf, size_t len))
{
	WRAPINIT(gnutls_record_send);

	ssize_t ret = _gnutls_record_send(s, buf, len);

	if (ret > 0)
		capture_session(0, s, buf, ret);

	return ret;
}

WRAP(ssize_t,gnutls_record_send_range,(gnutls_session_t s, const void *buf, size_t len, const gnutls_range_st *r))
{
	WRAPINIT(gnutls_record_send_range);

	ssize_t ret = _gnutls_record_send_range(s, buf, len, r);

	if (ret > 0)
		capture_session(0, s, buf, ret);

	return ret;
}
