/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
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

/* This file contains code for privilege separation. When an error arises in
 * monitor (which is running as root), it just stops instead of trying to
 * recover. This module also contains proxies to privileged operations. In this
 * case, error can be non fatal. */

#include "lldpd.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <regex.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>

enum {
	PRIV_PING,
	PRIV_CREATE_CTL_SOCKET,
	PRIV_DELETE_CTL_SOCKET,
	PRIV_GET_HOSTNAME,
	PRIV_OPEN,
	PRIV_ETHTOOL,
	PRIV_IFACE_INIT,
	PRIV_IFACE_MULTICAST,
	PRIV_SNMP_SOCKET,
};

static int may_read(int, void *, size_t);
static void must_read(int, void *, size_t);
static void must_write(int, void *, size_t);

static int remote;			/* Other side */
static int monitored = -1;		/* Child */
static int sock = -1;

/* UID/GID of unprivileged user */
static gid_t gid = 0;
static uid_t uid = 0;

/* Proxies */

static void
priv_ping()
{
	int cmd, rc;
	cmd = PRIV_PING;
	must_write(remote, &cmd, sizeof(int));
	must_read(remote, &rc, sizeof(int));
	LLOG_DEBUG("monitor ready");
}

/* Proxy for ctl_create, no argument since this is the monitor that decides the
 * location of the socket */
int
priv_ctl_create()
{
	int cmd, rc;
	cmd = PRIV_CREATE_CTL_SOCKET;
	must_write(remote, &cmd, sizeof(int));
	must_read(remote, &rc, sizeof(int));
	if (rc == -1)
		return -1;
	return receive_fd(remote);
}

/* Proxy for ctl_cleanup */
void
priv_ctl_cleanup()
{
	int cmd, rc;
	cmd = PRIV_DELETE_CTL_SOCKET;
	must_write(remote, &cmd, sizeof(int));
	must_read(remote, &rc, sizeof(int));
}

/* Proxy for gethostbyname */
char *
priv_gethostbyname()
{
	int cmd, rc;
	static char *buf = NULL;
	cmd = PRIV_GET_HOSTNAME;
	must_write(remote, &cmd, sizeof(int));
	must_read(remote, &rc, sizeof(int));
	if ((buf = (char*)realloc(buf, rc+1)) == NULL)
		fatal(NULL);
	must_read(remote, buf, rc+1);
	return buf;
}

/* Proxy for open */
int
priv_open(char *file)
{
	int cmd, len, rc;
	cmd = PRIV_OPEN;
	must_write(remote, &cmd, sizeof(int));
	len = strlen(file);
	must_write(remote, &len, sizeof(int));
	must_write(remote, file, len + 1);
	must_read(remote, &rc, sizeof(int));
	if (rc == -1)
		return rc;
	return receive_fd(remote);
}

/* Proxy for ethtool ioctl */
int
priv_ethtool(char *ifname, struct ethtool_cmd *ethc)
{
	int cmd, rc, len;
	cmd = PRIV_ETHTOOL;
	must_write(remote, &cmd, sizeof(int));
	len = strlen(ifname);
	must_write(remote, &len, sizeof(int));
	must_write(remote, ifname, len + 1);
	must_read(remote, &rc, sizeof(int));
	if (rc != 0)
		return rc;
	must_read(remote, ethc, sizeof(struct ethtool_cmd));
	return rc;
}

int
priv_iface_init(struct lldpd_hardware *hardware, int master)
{
	int cmd, rc;
	cmd = PRIV_IFACE_INIT;
	must_write(remote, &cmd, sizeof(int));
	must_write(remote, &master, sizeof(int));
	must_write(remote, hardware->h_ifname, IFNAMSIZ);
	must_read(remote, &rc, sizeof(int));
	if (rc != 0)
		return rc;	/* It's errno */
	hardware->h_raw = receive_fd(remote);
	return 0;
}

int
priv_iface_multicast(char *name, u_int8_t *mac, int add)
{
	int cmd, rc;
	cmd = PRIV_IFACE_MULTICAST;
	must_write(remote, &cmd, sizeof(int));
	must_write(remote, name, IFNAMSIZ);
	must_write(remote, mac, ETH_ALEN);
	must_write(remote, &add, sizeof(int));
	must_read(remote, &rc, sizeof(int));
	return rc;
}

int
priv_snmp_socket(struct sockaddr_un *addr)
{
	int cmd, rc;
	cmd = PRIV_SNMP_SOCKET;
	must_write(remote, &cmd, sizeof(int));
	must_write(remote, addr, sizeof(struct sockaddr_un));
	must_read(remote, &rc, sizeof(int));
	if (rc < 0)
		return rc;
	return receive_fd(remote);
}

static void
asroot_ping()
{
	int rc = 1;
	must_write(remote, &rc, sizeof(int));
}

static void
asroot_ctl_create()
{
	int rc;
	if ((rc = ctl_create(LLDPD_CTL_SOCKET)) == -1) {
		LLOG_WARN("[priv]: unable to create control socket");
		must_write(remote, &rc, sizeof(int));
		return;
	}
	if (chown(LLDPD_CTL_SOCKET, uid, gid) == -1)
		LLOG_WARN("[priv]: unable to chown control socket");
	if (chmod(LLDPD_CTL_SOCKET,
		S_IRUSR | S_IWUSR | S_IXUSR |
		S_IRGRP | S_IWGRP | S_IXGRP) == -1)
		LLOG_WARN("[priv]: unable to chmod control socket");
	must_write(remote, &rc, sizeof(int));
	send_fd(remote, rc);
	close(rc);
}

static void
asroot_ctl_cleanup()
{
	int rc = 0;
	ctl_cleanup(LLDPD_CTL_SOCKET);

	/* Ack */
	must_write(remote, &rc, sizeof(int));
}

static void
asroot_gethostbyname()
{
	struct utsname un;
	struct hostent *hp;
	int len;
	if (uname(&un) != 0)
		fatal("[priv]: failed to get system information");
	if ((hp = gethostbyname(un.nodename)) == NULL) {
                LLOG_WARN("[priv]: unable to get system name");
                len = strlen(un.nodename);
                must_write(remote, &len, sizeof(int));
                must_write(remote, un.nodename, len + 1);
        } else {
                len = strlen(hp->h_name);
                must_write(remote, &len, sizeof(int));
                must_write(remote, hp->h_name, len + 1);
        }
}

static void
asroot_open()
{
	const char* authorized[] = {
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/net/bonding/[^.][^/]*",
		"/proc/self/net/bonding/[^.][^/]*",
		SYSFS_CLASS_NET "[^.][^/]*/brforward",
		SYSFS_CLASS_NET "[^.][^/]*/brport",
		SYSFS_CLASS_DMI "product_version",
		SYSFS_CLASS_DMI "product_serial",
		SYSFS_CLASS_DMI "product_name",
		SYSFS_CLASS_DMI "bios_version",
		SYSFS_CLASS_DMI "sys_vendor",
		SYSFS_CLASS_DMI "chassis_asset_tag",
		NULL
	};
	char **f;
	char *file;
	int fd, len, rc;
	regex_t preg;

	must_read(remote, &len, sizeof(len));
	if ((file = (char *)malloc(len + 1)) == NULL)
		fatal(NULL);
	must_read(remote, file, len);
	file[len] = '\0';

	for (f=authorized; *f != NULL; f++) {
		if (regcomp(&preg, *f, REG_NOSUB) != 0)
			/* Should not happen */
			fatal("unable to compile a regex");
		if (regexec(&preg, file, 0, NULL, 0) == 0) {
			regfree(&preg);
			break;
		}
		regfree(&preg);
	}
	if (*f == NULL) {
		LLOG_WARNX("[priv]: not authorized to open %s", file);
		rc = -1;
		must_write(remote, &rc, sizeof(int));
		free(file);
		return;
	}
	if ((fd = open(file, O_RDONLY)) == -1) {
		rc = -1;
		must_write(remote, &rc, sizeof(int));
		free(file);
		return;
	}
	free(file);
	must_write(remote, &fd, sizeof(int));
	send_fd(remote, fd);
	close(fd);
}

static void
asroot_ethtool()
{
	struct ifreq ifr;
	struct ethtool_cmd ethc;
	int len, rc;
	char *ifname;

	memset(&ifr, 0, sizeof(ifr));
	memset(&ethc, 0, sizeof(ethc));
	must_read(remote, &len, sizeof(int));
	if ((ifname = (char*)malloc(len + 1)) == NULL)
		fatal(NULL);
	must_read(remote, ifname, len);
	ifname[len] = '\0';
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	free(ifname);
	ifr.ifr_data = (caddr_t)&ethc;
	ethc.cmd = ETHTOOL_GSET;
	if ((rc = ioctl(sock, SIOCETHTOOL, &ifr)) != 0) {
		LLOG_DEBUG("[priv]: unable to ioctl ETHTOOL for %s: %m",
		    ifr.ifr_name);
		must_write(remote, &rc, sizeof(int));
		return;
	}
	must_write(remote, &rc, sizeof(int));
	must_write(remote, &ethc, sizeof(struct ethtool_cmd));
}

static void
asroot_iface_init()
{
	struct sockaddr_ll sa;
	int un = 1;
	int s, master;
	char ifname[IFNAMSIZ];

	must_read(remote, &master, sizeof(int));
	must_read(remote, ifname, IFNAMSIZ);
	ifname[IFNAMSIZ-1] = '\0';

	/* Open listening socket to receive/send frames */
	if ((s = socket(PF_PACKET, SOCK_RAW,
		    htons(ETH_P_ALL))) < 0) {
		must_write(remote, &errno, sizeof(errno));
		return;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = 0;
	if (master == -1)
		sa.sll_ifindex = if_nametoindex(ifname);
	else
		sa.sll_ifindex = master;
	if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		must_write(remote, &errno, sizeof(errno));
		close(s);
		return;
	}

	if (master != -1) {
		/* With bonding, we need to listen to bond device. We use
		 * setsockopt() PACKET_ORIGDEV to get physical device instead of
		 * bond device */
		if (setsockopt(s, SOL_PACKET,
			PACKET_ORIGDEV, &un, sizeof(un)) == -1) {
			LLOG_WARN("[priv]: unable to setsockopt for master bonding device of %s. "
                            "You will get inaccurate results",
			    ifname);
                }
	}
	errno = 0;
	must_write(remote, &errno, sizeof(errno));
	send_fd(remote, s);
	close(s);
}

static void
asroot_iface_multicast()
{
	int add, rc = 0;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	must_read(remote, ifr.ifr_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	must_read(remote, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	must_read(remote, &add, sizeof(int));

	if (ioctl(sock, (add)?SIOCADDMULTI:SIOCDELMULTI,
		&ifr) < 0) {
		must_write(remote, &errno, sizeof(errno));
		return;
	}

	must_write(remote, &rc, sizeof(rc));
}

static void
asroot_snmp_socket()
{
	int sock, rc;
	static struct sockaddr_un *addr = NULL;
	struct sockaddr_un bogus;

	if (!addr) {
		addr = (struct sockaddr_un *)malloc(sizeof(struct sockaddr_un));
		must_read(remote, addr, sizeof(struct sockaddr_un));
	} else
		/* We have already been asked to connect to a socket. We will
		 * connect to the same socket. */
		must_read(remote, &bogus, sizeof(struct sockaddr_un));
	if (addr->sun_family != AF_UNIX)
		fatal("someone is trying to trick me");
	addr->sun_path[sizeof(addr->sun_path)-1] = '\0';

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		LLOG_WARN("[priv]: cannot open socket");
		must_write(remote, &sock, sizeof(int));
		return;
	}
        if ((rc = connect(sock, (struct sockaddr *) addr,
		    sizeof(struct sockaddr_un))) != 0) {
		LLOG_INFO("[priv]: cannot connect to %s: %s",
                          addr->sun_path, strerror(errno));
		close(sock);
		rc = -1;
		must_write(remote, &rc, sizeof(int));
		return;
        }
	must_write(remote, &rc, sizeof(int));
	send_fd(remote, sock);
	close(sock);
}

struct dispatch_actions {
	int				msg;
	void(*function)(void);
};

static struct dispatch_actions actions[] = {
	{PRIV_PING, asroot_ping},
	{PRIV_CREATE_CTL_SOCKET, asroot_ctl_create},
	{PRIV_DELETE_CTL_SOCKET, asroot_ctl_cleanup},
	{PRIV_GET_HOSTNAME, asroot_gethostbyname},
	{PRIV_OPEN, asroot_open},
	{PRIV_ETHTOOL, asroot_ethtool},
	{PRIV_IFACE_INIT, asroot_iface_init},
	{PRIV_IFACE_MULTICAST, asroot_iface_multicast},
	{PRIV_SNMP_SOCKET, asroot_snmp_socket},
	{-1, NULL}
};

/* Main loop, run as root */
static void
priv_loop()
{
	int cmd;
	struct dispatch_actions *a;

	while (!may_read(remote, &cmd, sizeof(int))) {
		for (a = actions; a->function != NULL; a++) {
			if (cmd == a->msg) {
				a->function();
				break;
			}
		}
		if (a->function == NULL)
			fatal("[priv]: bogus message received");
	}
	/* Should never be there */
}

static void
priv_exit()
{
	int status;
	int rc;
	if ((rc = waitpid(monitored, &status, WNOHANG)) == 0) {
		LLOG_DEBUG("[priv]: killing child");
		kill(monitored, SIGTERM);
	}
	if ((rc = waitpid(monitored, &status, WNOHANG)) == -1)
		_exit(0);
	LLOG_DEBUG("[priv]: waiting for child %d to terminate", monitored);
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
	LLOG_DEBUG("[priv]: received signal %d, exiting", sig);
	priv_exit();
}

/* Initialization */
void
priv_init(char *chrootdir)
{
	int pair[2];
	struct passwd *user;
	struct group *group;
	gid_t gidset[1];
        int status;

	/* Create socket pair */
	if (socketpair(AF_LOCAL, SOCK_DGRAM, PF_UNSPEC, pair) < 0)
		fatal("[priv]: unable to create socket pair for privilege separation");

	/* Get users */
	if ((user = getpwnam(PRIVSEP_USER)) == NULL)
		fatal("[priv]: no " PRIVSEP_USER " user for privilege separation");
	uid = user->pw_uid;
	if ((group = getgrnam(PRIVSEP_GROUP)) == NULL)
		fatal("[priv]: no " PRIVSEP_GROUP " group for privilege separation");
	gid = group->gr_gid;

	/* Spawn off monitor */
	if ((monitored = fork()) < 0)
		fatal("[priv]: unable to fork monitor");
	switch (monitored) {
	case 0:
		/* We are in the children, drop privileges */
		if (chroot(chrootdir) == -1)
			fatal("[priv]: unable to chroot");
		if (chdir("/") != 0)
			fatal("[priv]: unable to chdir");
		gidset[0] = gid;
		if (setresgid(gid, gid, gid) == -1)
			fatal("[priv]: setresgid() failed");
		if (setgroups(1, gidset) == -1)
			fatal("[priv]: setgroups() failed");
		if (setresuid(uid, uid, uid) == -1)
			fatal("[priv]: setresuid() failed");
		remote = pair[0];
		close(pair[1]);
		priv_ping();
		break;
	default:
		/* We are in the monitor */
		remote = pair[1];
		close(pair[0]);
		if (atexit(priv_exit) != 0)
			fatal("[priv]: unable to set exit function");
		if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			fatal("[priv]: unable to get a socket");
		}

		signal(SIGALRM, sig_pass_to_chld);
		signal(SIGTERM, sig_pass_to_chld);
		signal(SIGHUP, sig_pass_to_chld);
		signal(SIGINT, sig_pass_to_chld);
		signal(SIGQUIT, sig_pass_to_chld);
		signal(SIGCHLD, sig_chld);
                if (waitpid(monitored, &status, WNOHANG) != 0)
                        /* Child is already dead */
                        _exit(1);
		priv_loop();
		exit(0);
	}
}

/* Stolen from sbin/pflogd/privsep.c from OpenBSD */
/*
 * Copyright (c) 2003 Can Erkin Acar
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
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

/* Read all data or return 1 for error.  */
static int
may_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			return (1);
		default:
			pos += res;
		}
	}
	return (0);
}

/* Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh. */
static void
must_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}

/* Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh. */
static void
must_write(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = write(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}
