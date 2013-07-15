/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

/* This file contains code for privilege separation. When an error arises in
 * monitor (which is running as root), it just stops instead of trying to
 * recover. This module also contains proxies to privileged operations. In this
 * case, error can be non fatal. */

#include "lldpd.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/if_ether.h>

#if defined HOST_OS_FREEBSD || HOST_OS_OSX || HOST_OS_DRAGONFLY
# include <net/if_dl.h>
#endif
#if defined HOST_OS_SOLARIS
# include <sys/sockio.h>
#endif

/* Use resolv.h */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h> /* DNS HEADER struct */
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_RESOLV_H
#  include <resolv.h>
#endif

static int monitored = -1;		/* Child */

/* Proxies */
static void
priv_ping()
{
	int rc;
	enum priv_cmd cmd = PRIV_PING;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_read(&rc, sizeof(int));
	log_debug("privsep", "monitor ready");
}

/* Proxy for ctl_cleanup */
void
priv_ctl_cleanup(const char *ctlname)
{
	int rc, len = strlen(ctlname);
	enum priv_cmd cmd = PRIV_DELETE_CTL_SOCKET;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_write(&len, sizeof(int));
	must_write(ctlname, len);
	must_read(&rc, sizeof(int));
}

/* Proxy for gethostbyname */
char *
priv_gethostbyname()
{
	static char *buf = NULL;
	int rc;
	enum priv_cmd cmd = PRIV_GET_HOSTNAME;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_read(&rc, sizeof(int));
	if ((buf = (char*)realloc(buf, rc+1)) == NULL)
		fatal("privsep", NULL);
	must_read(buf, rc+1);
	return buf;
}


int
priv_iface_init(int index, char *iface)
{
	int rc;
	char dev[IFNAMSIZ];
	enum priv_cmd cmd = PRIV_IFACE_INIT;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_write(&index, sizeof(int));
	strlcpy(dev, iface, IFNAMSIZ);
	must_write(dev, IFNAMSIZ);
	must_read(&rc, sizeof(int));
	if (rc != 0) return -1;
	return receive_fd();
}

int
priv_iface_multicast(const char *name, u_int8_t *mac, int add)
{
	int rc;
	enum priv_cmd cmd = PRIV_IFACE_MULTICAST;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_write(name, IFNAMSIZ);
	must_write(mac, ETHER_ADDR_LEN);
	must_write(&add, sizeof(int));
	must_read(&rc, sizeof(int));
	return rc;
}

int
priv_iface_description(const char *name, const char *description)
{
	int rc, len = strlen(description);
	enum priv_cmd cmd = PRIV_IFACE_DESCRIPTION;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_write(name, IFNAMSIZ);
	must_write(&len, sizeof(int));
	must_write(description, len);
	must_read(&rc, sizeof(int));
	return rc;
}

int
priv_snmp_socket(struct sockaddr_un *addr)
{
	int rc;
	enum priv_cmd cmd = PRIV_SNMP_SOCKET;
	must_write(&cmd, sizeof(enum priv_cmd));
	must_write(addr, sizeof(struct sockaddr_un));
	must_read(&rc, sizeof(int));
	if (rc < 0)
		return rc;
	return receive_fd();
}

static void
asroot_ping()
{
	int rc = 1;
	must_write(&rc, sizeof(int));
}

static void
asroot_ctl_cleanup()
{
	int len;
	char *ctlname;
	int rc = 0;

	must_read(&len, sizeof(int));
	if ((ctlname = (char*)malloc(len+1)) == NULL)
		fatal("ctlname", NULL);

	must_read(ctlname, len);
	ctlname[len] = 0;

	ctl_cleanup(ctlname);
	free(ctlname);

	/* Ack */
	must_write(&rc, sizeof(int));
}

static void
asroot_gethostbyname()
{
	struct utsname un;
	struct hostent *hp;
	int len;
	if (uname(&un) < 0)
		fatal("privsep", "failed to get system information");
	if ((hp = gethostbyname(un.nodename)) == NULL) {
		log_info("privsep", "unable to get system name");
#ifdef HAVE_RES_INIT
		res_init();
#endif
                len = strlen(un.nodename);
                must_write(&len, sizeof(int));
                must_write(un.nodename, len + 1);
        } else {
                len = strlen(hp->h_name);
                must_write(&len, sizeof(int));
                must_write(hp->h_name, len + 1);
        }
}

static void
asroot_iface_init()
{
	int rc = -1, fd = -1;
	int ifindex;
	char name[IFNAMSIZ];
	must_read(&ifindex, sizeof(ifindex));
	must_read(&name, sizeof(name));
	name[sizeof(name) - 1] = '\0';

	rc = asroot_iface_init_os(ifindex, name, &fd);
	must_write(&rc, sizeof(rc));
	if (rc == 0 && fd >=0) send_fd(fd);
	if (fd >= 0) close(fd);
}

static void
asroot_iface_multicast()
{
	int sock = -1, add, rc = 0;
	struct ifreq ifr = { .ifr_name = {} };
	must_read(ifr.ifr_name, IFNAMSIZ);
#if defined HOST_OS_LINUX
	must_read(ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
#elif defined HOST_OS_FREEBSD || defined HOST_OS_OSX || defined HOST_OS_DRAGONFLY
	/* Black magic from mtest.c */
	struct sockaddr_dl *dlp = (struct sockaddr_dl *)&ifr.ifr_addr;
	dlp->sdl_len = sizeof(struct sockaddr_dl);
	dlp->sdl_family = AF_LINK;
	dlp->sdl_index = 0;
	dlp->sdl_nlen = 0;
	dlp->sdl_alen = ETHER_ADDR_LEN;
	dlp->sdl_slen = 0;
	must_read(LLADDR(dlp), ETHER_ADDR_LEN);
#elif defined HOST_OS_OPENBSD || defined HOST_OS_NETBSD || defined HOST_OS_SOLARIS
	struct sockaddr *sap = (struct sockaddr *)&ifr.ifr_addr;
#if ! defined HOST_OS_SOLARIS
	sap->sa_len = sizeof(struct sockaddr);
#endif
	sap->sa_family = AF_UNSPEC;
	must_read(sap->sa_data, ETHER_ADDR_LEN);
#else
#error Unsupported OS
#endif

	must_read(&add, sizeof(int));
	if (((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) ||
	    ((ioctl(sock, (add)?SIOCADDMULTI:SIOCDELMULTI,
		    &ifr) < 0) && (errno != EADDRINUSE)))
		rc = errno;

	if (sock != -1) close(sock);
	must_write(&rc, sizeof(rc));
}

static void
asroot_iface_description()
{
	char name[IFNAMSIZ];
	char *description;
	int len, rc;
	must_read(&name, sizeof(name));
	name[sizeof(name) - 1] = '\0';
	must_read(&len, sizeof(int));
	if ((description = (char*)malloc(len+1)) == NULL)
		fatal("description", NULL);

	must_read(description, len);
	description[len] = 0;
	rc = asroot_iface_description_os(name, description);
	must_write(&rc, sizeof(rc));
}

static void
asroot_snmp_socket()
{
	int sock, rc;
	static struct sockaddr_un *addr = NULL;
	struct sockaddr_un bogus;

	if (!addr) {
		addr = (struct sockaddr_un *)malloc(sizeof(struct sockaddr_un));
		must_read(addr, sizeof(struct sockaddr_un));
	} else
		/* We have already been asked to connect to a socket. We will
		 * connect to the same socket. */
		must_read(&bogus, sizeof(struct sockaddr_un));
	if (addr->sun_family != AF_UNIX)
		fatal("privsep", "someone is trying to trick me");
	addr->sun_path[sizeof(addr->sun_path)-1] = '\0';

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		log_warn("privsep", "cannot open socket");
		must_write(&sock, sizeof(int));
		return;
	}
        if ((rc = connect(sock, (struct sockaddr *) addr,
		    sizeof(struct sockaddr_un))) != 0) {
		log_info("privsep", "cannot connect to %s: %s",
                          addr->sun_path, strerror(errno));
		close(sock);
		rc = -1;
		must_write(&rc, sizeof(int));
		return;
        }
	must_write(&rc, sizeof(int));
	send_fd(sock);
	close(sock);
}

struct dispatch_actions {
	enum priv_cmd msg;
	void(*function)(void);
};

static struct dispatch_actions actions[] = {
	{PRIV_PING, asroot_ping},
	{PRIV_DELETE_CTL_SOCKET, asroot_ctl_cleanup},
	{PRIV_GET_HOSTNAME, asroot_gethostbyname},
#ifdef HOST_OS_LINUX
	{PRIV_OPEN, asroot_open},
	{PRIV_ETHTOOL, asroot_ethtool},
#endif
	{PRIV_IFACE_INIT, asroot_iface_init},
	{PRIV_IFACE_MULTICAST, asroot_iface_multicast},
	{PRIV_IFACE_DESCRIPTION, asroot_iface_description},
	{PRIV_SNMP_SOCKET, asroot_snmp_socket},
	{-1, NULL}
};

/* Main loop, run as root */
static void
priv_loop()
{
	enum priv_cmd cmd;
	struct dispatch_actions *a;

	setproctitle("monitor");
	while (!may_read(&cmd, sizeof(enum priv_cmd))) {
		for (a = actions; a->function != NULL; a++) {
			if (cmd == a->msg) {
				a->function();
				break;
			}
		}
		if (a->function == NULL)
			fatal("privsep", "bogus message received");
	}
	/* Should never be there */
}

static void
priv_exit_rc_status(int rc, int status) {
	switch (rc) {
	case 0:
		log_debug("privsep", "killing child");
		kill(monitored, SIGTERM);
		log_debug("privsep", "waiting for child %d to terminate", monitored);
		return;
	case -1:
		log_debug("privsep", "child does not exist anymore");
		_exit(1);	/* We consider this is an error to be here */
		break;
	default:
		log_debug("privsep", "monitored child has terminated");
		/* Mimic the exit state of the child */
		if (WIFEXITED(status)) {
			log_debug("privsep", "monitored child has terminated with status %d",
			    WEXITSTATUS(status));
			_exit(WEXITSTATUS(status));
		}
		if (WIFSIGNALED(status)) {
			log_debug("privsep", "monitored child has terminated with signal %d",
			    WTERMSIG(status));
			signal(WTERMSIG(status), SIG_DFL);
			raise(WTERMSIG(status));
			_exit(1); /* We consider that not being killed is an error. */
		}
		/* Other cases, consider this as an error. */
		_exit(1);
		break;
	}
}

static void
priv_exit()
{
	int status;
	int rc;
	rc = waitpid(monitored, &status, WNOHANG);
	priv_exit_rc_status(rc, status);
}

/* If priv parent gets a TERM or HUP, pass it through to child instead */
static void
sig_pass_to_chld(int sig)
{
	int oerrno = errno;
	if (monitored != -1)
		kill(monitored, sig);
	errno = oerrno;
}

/* if parent gets a SIGCHLD, it will exit */
static void
sig_chld(int sig)
{
	int status;
	int rc = waitpid(monitored, &status, WNOHANG);
	if (rc == 0) {
		while ((rc = waitpid(-1, &status, WNOHANG)) > 0) {
			if (rc == monitored) priv_exit_rc_status(rc, status);
			else log_debug("privsep", "unrelated process %d has died",
				rc);
		}
		return;
	}
	priv_exit_rc_status(rc, status);
}

/* Initialization */
void
priv_init(const char *chrootdir, int ctl, uid_t uid, gid_t gid)
{

	int pair[2];
	gid_t gidset[1];
        int status;

	/* Create socket pair */
	if (socketpair(AF_LOCAL, SOCK_DGRAM, PF_UNSPEC, pair) < 0)
		fatal("privsep", "unable to create socket pair for privilege separation");

	/* Spawn off monitor */
	if ((monitored = fork()) < 0)
		fatal("privsep", "unable to fork monitor");
	switch (monitored) {
	case 0:
		/* We are in the children, drop privileges */
		if (RUNNING_ON_VALGRIND)
			log_warnx("privsep", "running on valgrind, keep privileges");
		else {
			struct stat schroot;
			if (stat(chrootdir, &schroot) == -1) {
				if (errno != ENOENT)
					fatal("privsep", "chroot directory does not exist");
				if (mkdir(chrootdir, 0755) == -1)
					fatal("privsep", "unable to create chroot directory");
				log_info("privsep", "created chroot directory %s",
				    chrootdir);
			}
			if (chroot(chrootdir) == -1)
				fatal("privsep", "unable to chroot");
			if (chdir("/") != 0)
				fatal("privsep", "unable to chdir");
			gidset[0] = gid;
#ifdef HAVE_SETRESGID
			if (setresgid(gid, gid, gid) == -1)
				fatal("privsep", "setresgid() failed");
#else
			if (setregid(gid, gid) == -1)
				fatal("privsep", "setregid() failed");
#endif
			if (setgroups(1, gidset) == -1)
				fatal("privsep", "setgroups() failed");
#ifdef HAVE_SETRESUID
			if (setresuid(uid, uid, uid) == -1)
				fatal("privsep", "setresuid() failed");
#else
			if (setreuid(uid, uid) == -1)
				fatal("privsep", "setreuid() failed");
#endif
		}
		priv_remote(pair[0]);
		close(pair[1]);
		priv_ping();
		break;
	default:
		/* We are in the monitor */
		if (ctl != -1) close(ctl);
		priv_remote(pair[1]);
		close(pair[0]);
		if (atexit(priv_exit) != 0)
			fatal("privsep", "unable to set exit function");

		/* Install signal handlers */
		const struct sigaction pass_to_child = {
			.sa_handler = sig_pass_to_chld,
			.sa_flags = SA_RESTART
		};
		sigaction(SIGALRM, &pass_to_child, NULL);
		sigaction(SIGTERM, &pass_to_child, NULL);
		sigaction(SIGHUP,  &pass_to_child, NULL);
		sigaction(SIGINT,  &pass_to_child, NULL);
		sigaction(SIGQUIT, &pass_to_child, NULL);
		const struct sigaction child = {
			.sa_handler = sig_chld,
			.sa_flags = SA_RESTART
		};
		sigaction(SIGCHLD, &child, NULL);

                if (waitpid(monitored, &status, WNOHANG) != 0)
                        /* Child is already dead */
                        _exit(1);
		priv_loop();
		exit(0);
	}
}

