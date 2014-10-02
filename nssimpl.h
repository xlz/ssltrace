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

#ifndef NSSIMPL_H
#define NSSIMPL_H

#include <nss/seccomon.h> /* SECItem */
#include <nspr/prio.h> /* PRFileDesc */

typedef struct {
	void *connect;
	void *accept;
	void *bind;
	void *listen;
	void *shutdown;
	void *close;
	int (*recv)(void *, unsigned char *, int, int);
	int (*send)(void *, const unsigned char *, int, int);
	int (*read)(void *, unsigned char *, int);
	int (*write)(void *, const unsigned char *, int);
	void *getpeername;
	void *getsockname;
} sslSocketOps;

typedef struct {
	SECItem nextProtoNego;
	unsigned int useSecurity:1;
	unsigned int :28;
} sslOptions;

typedef struct {
	PRFileDesc *fd;
	const sslSocketOps *ops;
	sslOptions opt;
	char dont_access_beyond_this[];
} sslSocket;

#endif // NSSIMPL_H
