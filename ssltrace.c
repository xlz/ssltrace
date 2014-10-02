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

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

typedef struct {
	const char *symbol;
	void *self;
	void **ret;
} DLIteratePhdrCallbackClosure;

static int ssltrace_dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *cbdata)
{
	DLIteratePhdrCallbackClosure* data = (DLIteratePhdrCallbackClosure*)cbdata;

	/* Ignore main program and ssltrace lib */
	if (!info->dlpi_addr || !info->dlpi_name || !info->dlpi_name[0] || data->self == (void*)info->dlpi_addr)
		return 0;
	
	/* Not sure how to input info->dlpi_addr into dlsym, so just use dlopen */
	void *dlh = dlopen(info->dlpi_name, RTLD_LAZY);
	*(data->ret) = dlsym(dlh, data->symbol);
	if (*(data->ret)) {
		/* stop if we found something */
		return 1;
	} else {
		dlclose(dlh);
		return 0;
	}
}

void *ssltrace_dlsym(const char *symbol)
{
	void *ret = dlsym(RTLD_NEXT, symbol);
	if (!ret) {
	/* dlsym failed, try iterating all loaded libraries manually */
		static Dl_info dli = {0};
		DLIteratePhdrCallbackClosure data = {symbol, 0, &ret};
		if (!dli.dli_fbase && !dladdr((void*)ssltrace_dlsym, &dli))
			ssltrace_die("Unable to find information about " SSLTRACE " module.");
		data.self = dli.dli_fbase;
		dl_iterate_phdr(&ssltrace_dl_iterate_phdr_callback, &data);
	}
	return ret;
}

void ssltrace_debug(const char* fmt, ...)
{
	va_list ap;

	fputs(SSLTRACE ": ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	fflush(stderr);
}

void ssltrace_die(const char* message)
{
	fprintf(stderr, SSLTRACE ": %s\n", message);
	fflush(stderr);
	exit(1);
}

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <sys/resource.h>

typedef union {
	struct sockaddr s;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} sockaddr_t;

static int filestat(int fd, struct stat *sb)
{
	static rlim_t max_files = RLIM_INFINITY;
	static int got;
	if (!got) {
		got = 1;
		struct rlimit rlim;
		getrlimit(RLIMIT_NOFILE, &rlim);
		max_files = rlim.rlim_max;
	}
	if (fd > max_files)
		return -1;
	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
		return -1;
	return fstat(fd, sb);
}

static void get_addresses(uint64_t entropy[2], sockaddr_t *local, sockaddr_t *remote)
{
	socklen_t addrlen = sizeof(*local);

	uint32_t addr[2];
	uint16_t port[2];
	addr[0] = entropy[0] >> 16;
	port[0] = entropy[0] & 0xffff;
	addr[1] = entropy[1] >> 16;
	port[1] = entropy[1] & 0xffff;

	struct stat sb;
	int fd = entropy[0];
	if (filestat(fd, &sb) == 0) {
		port[0] = sb.st_ino & 0xffff;
		addr[0] = (sb.st_ino >> 16) ^ (sb.st_dev << 24);
		port[1] += port[0];
		addr[1] += port[0];
		if (S_ISSOCK(sb.st_mode) && getsockname(fd, &local->s, &addrlen) == 0) {
			sa_family_t af = local->s.sa_family;
			if (af == AF_INET || af == AF_INET6)
				if (getpeername(fd, &remote->s, &addrlen) == 0)
					return;
			if (af == AF_INET6) {
				remote->v6.sin6_port = htons(port[1]);
				remote->v6.sin6_addr.s6_addr32[0] = htonl(0x20010db8);
				remote->v6.sin6_addr.s6_addr32[1] = 0;
				remote->v6.sin6_addr.s6_addr32[2] = 0;
				remote->v6.sin6_addr.s6_addr32[3] = htonl(addr[1]);
				return;
			}
			if (af == AF_INET) {
				remote->v4.sin_port = htons(port[1]);
				remote->v4.sin_addr.s_addr = htonl(addr[1]);
				return;
			}
		}
	}
	local->s.sa_family = AF_INET;
	local->v4.sin_port = htons(port[0]);
	local->v4.sin_addr.s_addr = htonl(addr[0]);
	remote->v4.sin_port = htons(port[1]);
	remote->v4.sin_addr.s_addr = htonl(addr[1]);
}

static FILE *open_capture_file()
{
	const char *flog = getenv(SSLTRACE_PCAP);
	if (!flog || !strlen(flog))
		return NULL;
	FILE *fp = fopen(flog, "a");
	if (!fp)
		return fp;

	struct {
		uint32_t magic_number;
		uint16_t version_major, version_minor;
		int32_t thiszone;
		uint32_t sigfigs, snaplen, network;
	} pcap_header = {0xa1b2c3d4, 2, 4, 0, 0, 65535, 101/*RAW_IP*/};

	if (ftello(fp) == 0)
		fwrite(&pcap_header, sizeof(pcap_header), 1, fp);

	return fp;
}

void ssltrace_capture_payload(int read, uint64_t entropy[2], const char *buf, unsigned long len)
{
	static FILE *fp;
	static int configured;
	if (!configured) {
		configured = 1;
		fp = open_capture_file();
		if (!fp)
			ssltrace_debug(SSLTRACE_PCAP " not set, not saving capture");
	}
	if (!fp)
		return;

	sockaddr_t local, remote, *src = &local, *dst = &remote;
	if (read) {
		src = &remote;
		dst = &local;
	}

	get_addresses(entropy, &local, &remote);

	union {
		struct iphdr v4;
		struct ip6_hdr v6;
	} ip = {{0}};
	if (local.s.sa_family == AF_INET) {
		ip.v4.ihl = sizeof(ip.v4) >> 2;
		ip.v4.version = IPVERSION;
		ip.v4.ttl = IPDEFTTL;
		ip.v4.protocol = IPPROTO_UDP;
		ip.v4.saddr = src->v4.sin_addr.s_addr;
		ip.v4.daddr = dst->v4.sin_addr.s_addr;
	} else {
		ip.v6.ip6_flow = htonl(6 << 28);
		ip.v6.ip6_nxt = IPPROTO_UDP;
		ip.v6.ip6_hops = IPDEFTTL;
		ip.v6.ip6_src = src->v6.sin6_addr;
		ip.v6.ip6_dst = dst->v6.sin6_addr;
	}

	struct udphdr udp = {{{0}}};
	udp.source = src->v4.sin_port;
	udp.dest = dst->v4.sin_port;

	int plen;
	for (; len > 0; len -= plen, buf += plen) {
		plen = len;
		const int MAX_PAYLOAD = 61440;
		if (plen > MAX_PAYLOAD)
			plen = MAX_PAYLOAD;

		struct timeval now;
		gettimeofday(&now, NULL);

		struct {
			uint32_t ts_sec, ts_usec, incl_len, orig_len;
		} pcaprec_header = {(uint32_t)now.tv_sec, (uint32_t)now.tv_usec, (uint32_t)sizeof(udp) + plen};
		udp.len = htons(sizeof(udp) + plen);

		if (local.s.sa_family == AF_INET) {
			pcaprec_header.incl_len += sizeof(ip.v4);
			ip.v4.tot_len = htons(sizeof(ip.v4) + sizeof(udp) + plen);
		} else {
			pcaprec_header.incl_len += sizeof(ip.v6);
			ip.v6.ip6_plen = udp.len;
		}
		pcaprec_header.orig_len = pcaprec_header.incl_len;

		fwrite(&pcaprec_header, sizeof(pcaprec_header), 1, fp);
		fwrite(&ip, pcaprec_header.incl_len - sizeof(udp) - plen, 1, fp);
		fwrite(&udp, sizeof(udp), 1, fp);
		fwrite(buf, plen, 1, fp);
	}
	fflush(fp);
}
