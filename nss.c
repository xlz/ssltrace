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

#include <nspr/nspr.h>
#include <nspr/private/pprio.h> /* PR_FileDesc2NativeHandle */
#include "nssimpl.h"

#include <dlfcn.h>
#include <string.h>

// Adapted from sslsock.c
static PRDescIdentity ssl_layer_id = PR_INVALID_IO_LAYER;
sslSocket* ssl_FindSocket(PRFileDesc *fd)
{
	PRFileDesc *layer;
	sslSocket *ss;

	PORT_Assert(fd != NULL);
	PORT_Assert(ssl_layer_id != PR_INVALID_IO_LAYER);

	layer = PR_GetIdentitiesLayer(fd, ssl_layer_id);
	if (layer == NULL)
		return NULL;

	ss = (sslSocket *)layer->secret;
	ss->fd = layer;
	return ss;
}

static void capture_session(int read, void *vp, const unsigned char *buf, size_t len)
{
	sslSocket *ss = (sslSocket *)vp;
	PRErrorCode error = PR_GetError();
	PRInt32 oserror = PR_GetOSError();
	int fd = PR_FileDesc2NativeHandle(ss->fd);
	
	uint64_t entropy[2] = {fd, (uint64_t)vp};
	if (fd < 0) {
		PR_SetError(error, oserror);
		entropy[0] = (uint64_t)vp;
		PRNetAddr addr;
		if (ss->fd->methods->getpeername && ss->fd->methods->getpeername(ss->fd, &addr) == 0) {
			if (addr.raw.family == PR_AF_INET) {
				entropy[1] = (PR_ntohl(addr.inet.ip) << 16) | PR_ntohs(addr.inet.port);
			} else if (addr.raw.family == PR_AF_INET6) {
				entropy[1] = PR_ntohl(addr.ipv6.ip.pr_s6_addr32[0]);
				entropy[1] += PR_ntohl(addr.ipv6.ip.pr_s6_addr32[1]);
				entropy[1] += PR_ntohl(addr.ipv6.ip.pr_s6_addr32[2]);
				entropy[1] += PR_ntohl(addr.ipv6.ip.pr_s6_addr32[3]);
				entropy[1] = (entropy[1] << 16) | PR_ntohs(addr.ipv6.port);
			} else {
				entropy[1] = *(uint64_t *)addr.raw.data;
			}
		} else {
			entropy[1] = (uint64_t)ss->fd;
		}
	}
	ssltrace_capture_payload(read, entropy, (const char *)buf, len);
}

/*
ssl_SecureRead
  ss->ops = sslSocketOpsStr.read
    ssl_ChooseOps
      PrepareSocket
        SSL_OptionSet*
          SSL_Enable
      ssl_NewSocket
        ssl_DupSocket
          ssl_ImportFD
          ssl_Accept
            ssl_methods
              ssl_SetupIOMethods
                ssl_InitIOLayer
                  ssl_PushIOLayer
        ssl_ImportFD
          SSL_ImportFD*
          DTLS_ImportFD*
*/
static const sslSocketOps *_ssl_secure_ops;
static sslSocketOps ssl_secure_ops;

static int ssl_SecureRecv(void *ss, unsigned char *buf, int len, int flags)
{
	int ret = _ssl_secure_ops->recv(ss, buf, len, flags);
	if (ret > 0)
		capture_session(1, ss, buf, ret);
	return ret;
}

static int ssl_SecureSend(void *ss, const unsigned char *buf, int len, int flags)
{
	int ret = _ssl_secure_ops->send(ss, buf, len, flags);
	if (ret > 0)
		capture_session(0, ss, buf, ret);
	return ret;
}

static int ssl_SecureRead(void *ss, unsigned char *buf, int len)
{
	int ret = _ssl_secure_ops->read(ss, buf, len);
	if (ret > 0)
		capture_session(1, ss, buf, ret);
	return ret;
}

static int ssl_SecureWrite(void *ss, const unsigned char *buf, int len)
{
	int ret = _ssl_secure_ops->write(ss, buf, len);
	if (ret > 0)
		capture_session(0, ss, buf, ret);
	return ret;
}

static void override_ssl_ops(PRFileDesc *fd)
{
	if (!fd)
		return;

	sslSocket * ss = ssl_FindSocket(fd);
	if (!ss || !ss->opt.useSecurity)
		return;

	if (!_ssl_secure_ops) {
		_ssl_secure_ops = ss->ops;
		ssl_secure_ops = *_ssl_secure_ops;
		ssl_secure_ops.recv = ssl_SecureRecv;
		ssl_secure_ops.send = ssl_SecureSend;
		ssl_secure_ops.read = ssl_SecureRead;
		ssl_secure_ops.write = ssl_SecureWrite;
	}
	if (ss->ops->recv != ssl_SecureRecv)
		ss->ops = &ssl_secure_ops;
}

static PRIOMethods _combined_methods;

static PRInt32 ssl_Read(PRFileDesc *fd, void *buf, PRInt32 len)
{
	override_ssl_ops(fd);
	return _combined_methods.read(fd, buf, len);
}

static PRInt32 ssl_Write(PRFileDesc *fd, const void *buf, PRInt32 len)
{
	override_ssl_ops(fd);
	return _combined_methods.write(fd, buf, len);
}

static PRInt32 ssl_Recv(PRFileDesc *fd, void *buf, PRInt32 len, PRIntn flags, PRIntervalTime timeout)
{
	override_ssl_ops(fd);
	return _combined_methods.recv(fd, buf, len, flags, timeout);
}

static PRInt32 ssl_Send(PRFileDesc *fd, const void *buf, PRInt32 len, PRIntn flags, PRIntervalTime timeout)
{
	override_ssl_ops(fd);
	return _combined_methods.send(fd, buf, len, flags, timeout);
}

/*
SSL_ImportFD
DTLS_ImportFD
  ssl_ImportFD
  ssl_Accept
    ssl_PushIOLayer
      PR_CreateIOLayerStub
      PR_PushIOLayer
*/
WRAP(PRFileDesc*,PR_CreateIOLayerStub,(PRDescIdentity id, const PRIOMethods *methods))
{
	WRAPINIT(PR_CreateIOLayerStub);


	if (ssl_layer_id == PR_INVALID_IO_LAYER) {
		const char *name = PR_GetNameForIdentity(id);
		if (name && strcmp(name, "SSL") == 0) {
			ssl_layer_id = id;
			_combined_methods = *methods;
			PRIOMethods *m = (PRIOMethods *)methods;
			m->recv = ssl_Recv;
			m->send = ssl_Send;
			m->read = ssl_Read;
			m->write = ssl_Write;
		}
	}

	PRFileDesc *ret = _PR_CreateIOLayerStub(id, methods);
	if (!ret)
		return ret;

	return ret;
}
