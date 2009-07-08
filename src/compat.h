/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

#if !HAVE_DECL_TAILQ_FIRST
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#endif

#if !HAVE_DECL_TAILQ_NEXT
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#endif

#if !HAVE_DECL_TAILQ_FOREACH
#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = ((head)->tqh_first);				\
		(var);							\
		(var) = ((var)->field.tqe_next))
#endif

#if !HAVE_DECL_TAILQ_EMPTY
#define	TAILQ_EMPTY(head)		((head)->tqh_first == NULL)
#endif

#if !HAVE_DECL_SLIST_HEAD
#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}
#endif

#if !HAVE_DECL_SLIST_ENTRY
#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}
#endif

#if !HAVE_DECL_SLIST_INIT
#define	SLIST_INIT(head) do {						\
	(head)->slh_first = NULL;					\
} while (/*CONSTCOND*/0)
#endif

#if !HAVE_DECL_SLIST_INSERT_HEAD
#define	SLIST_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} while (/*CONSTCOND*/0)
#endif

#if !HAVE_DECL_SLIST_REMOVE_HEAD
#define	SLIST_REMOVE_HEAD(head, field) do {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} while (/*CONSTCOND*/0)
#endif

#if !HAVE_DECL_SLIST_EMPTY
#define	SLIST_EMPTY(head)	((head)->slh_first == NULL)
#endif

#if !HAVE_DECL_SLIST_FIRST
#define	SLIST_FIRST(head)	((head)->slh_first)
#endif

#if !HAVE_DECL_SLIST_NEXT
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_next)
#endif

#if !HAVE_DECL_ADVERTISED_PAUSE
#define ADVERTISED_Pause (1 << 13)
#endif

#if !HAVE_DECL_ADVERTISED_ASYM_PAUSE
#define ADVERTISED_Asym_Pause (1 << 14)
#endif

#if !HAVE_DECL_ADVERTISED_2500BASEX_Full
#define ADVERTISED_2500baseX_Full (1 << 15)
#endif

#if !HAVE_DECL_PACKET_ORIGDEV
#define PACKET_ORIGDEV 9
#endif

#if !HAVE_DECL_ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#if !HAVE_GETIFADDRS
struct ifaddrs {
	struct ifaddrs  *ifa_next;    /* Next item in list */
	char            *ifa_name;    /* Name of interface */
	unsigned int     ifa_flags;   /* Flags from SIOCGIFFLAGS */
	struct sockaddr *ifa_addr;    /* Address of interface */
	struct sockaddr *ifa_netmask; /* Netmask of interface */
	/* At most one of the following two is valid.  If the IFF_BROADCAST
	   bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
	   IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
	   It is never the case that both these bits are set at once.  */
	union {
		struct sockaddr *ifu_broadaddr;
		/* Broadcast address of interface */
		struct sockaddr *ifu_dstaddr;
		/* Point-to-point destination address */
	} ifa_ifu;
# ifndef ifa_broadaddr
#  define              ifa_broadaddr ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define              ifa_dstaddr   ifa_ifu.ifu_dstaddr
# endif
	void            *ifa_data;    /* Address-specific data */
};

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);
#endif

#if !HAVE_STRLCPY
size_t	strlcpy(char *, const char *, size_t);
#endif
