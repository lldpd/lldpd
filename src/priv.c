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
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#include <netdb.h>

int remote;			/* Other side */
int monitored;			/* Child */

/* Message to be sent between monitor and child. The convention is that both
 * ends agree on the content (value) which depends on the message and on the
 * direction. */
struct priv_msg {
	enum {
		PRIV_FORK,
		PRIV_CREATE_CTL_SOCKET,
		PRIV_DELETE_CTL_SOCKET,
		PRIV_GET_HOSTNAME,
		PRIV_OPEN,
	}		 msg;
	union {
		int	 integer;
		char	 iface[IFNAMSIZ];
		char	 buf[1024];
	}		 value;
};

int
priv_send(struct priv_msg *msg)
{
	if (write(remote, msg, sizeof(struct priv_msg)) !=
	    sizeof(struct priv_msg)) {
		LLOG_WARN("unable to send message");
		errno = EPIPE;
		return -1;
	}
	if (read(remote, msg, sizeof(struct priv_msg)) !=
	    sizeof(struct priv_msg)) {
		LLOG_WARN("unable to get answer");
		errno = EPIPE;
		return -1;
	}
	return 0;
}

/* Run as root */
void
priv_send_back(struct priv_msg *msg)
{
	if (write(remote, msg, sizeof(struct priv_msg)) !=
	    sizeof(struct priv_msg)) {
		fatal("unable to send message");
	}
}

/* Run as root */
void
priv_send_fd(int fd)
{
	struct msghdr	 msg = {0};
	struct cmsghdr	*cmsg;
	char		 buf[CMSG_SPACE(sizeof(int))];

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
	if (sendmsg(remote, &msg, 0) == -1) {
		LLOG_WARN("unable to send file descriptor %d", fd);
		fatal(NULL);
	}
}

int
priv_get_fd()
{
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	char		 buf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(remote, &msg, 0) == -1) {
		LLOG_WARN("unable to receive file descriptor");
		return -1;
	}
	if ((cmsg = CMSG_FIRSTHDR(&msg)) == NULL) {
		LLOG_WARNX("no file descriptor in received message");
		return -1;
	}
	if (CMSG_NXTHDR(&msg, cmsg) != NULL) {
		LLOG_WARNX("more than one file descriptor received");
		return -1;
	}
	if ((cmsg->cmsg_level != SOL_SOCKET) ||
	    (cmsg->cmsg_type != SCM_RIGHTS)) {
		LLOG_WARNX("unknown control data received (%d, %d)",
		    cmsg->cmsg_level, cmsg->cmsg_type);
		return -1;
	}
	return (*(int *)CMSG_DATA(cmsg));
}

/* Proxies */

/* Proxy for fork */
void
priv_fork()
{
	struct priv_msg(msg);
	msg.msg = PRIV_FORK;
	priv_send(&msg);
}

/* Proxy for ctl_create, no argument since this is the monitor that decides the
 * location of the socket */
int
priv_ctl_create()
{
	struct priv_msg msg;
	msg.msg = PRIV_CREATE_CTL_SOCKET;
	if ((priv_send(&msg) == -1) ||
	    (msg.value.integer == -1))
		return -1;
	return priv_get_fd();
}

/* Proxy for ctl_cleanup */
void
priv_ctl_cleanup()
{
	struct priv_msg msg;
	msg.msg = PRIV_DELETE_CTL_SOCKET;
	priv_send(&msg);
}

/* Proxy for gethostbyname */
char *
priv_gethostbyname()
{
	static struct priv_msg msg;
	msg.msg = PRIV_GET_HOSTNAME;
	if (priv_send(&msg) == -1)
		fatal("unable to get hostname");
	return msg.value.buf;
}

/* Proxy for open */
int
priv_open(char *file)
{
	struct priv_msg msg;
	msg.msg = PRIV_OPEN;
	if (strlen(file) >= sizeof(msg.value.buf)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strlcpy(msg.value.buf, file, sizeof(msg.value.buf));
	if ((priv_send(&msg) == -1) ||
	    (msg.value.integer == -1))
		return -1;
	return priv_get_fd();
}

void
priv_fork_daemon(struct priv_msg *msg)
{
	int pid;
	char *spid;
	if (daemon(0, 0) != 0)
		fatal("failed to detach daemon");
	if ((pid = open(LLDPD_PID_FILE,
		    O_TRUNC | O_CREAT | O_WRONLY)) == -1)
		fatal("unable to open pid file " LLDPD_PID_FILE);
	if (asprintf(&spid, "%d\n", getpid()) == -1)
		fatal("unable to create pid file " LLDPD_PID_FILE);
	if (write(pid, spid, strlen(spid)) == -1)
		fatal("unable to write pid file " LLDPD_PID_FILE);
	free(spid);
	close(pid);
}

void
priv_create_ctl_socket(struct priv_msg *msg)
{
	if ((msg->value.integer =
		ctl_create(LLDPD_CTL_SOCKET)) == -1) {
		LLOG_WARN("unable to create control socket");
		priv_send_back(msg);
	} else {
		priv_send_back(msg);
		priv_send_fd(msg->value.integer);
		close(msg->value.integer);
	}
}

void
priv_delete_ctl_socket(struct priv_msg *msg)
{
	ctl_cleanup(LLDPD_CTL_SOCKET);
	priv_send_back(msg);
}

void
priv_get_hostname(struct priv_msg *msg)
{
	struct utsname un;
	struct hostent *hp;
	if (uname(&un) != 0)
		fatal("failed to get system information");
	if ((hp = gethostbyname(un.nodename)) == NULL)
		fatal("failed to get system name");
	strlcpy(msg->value.buf, hp->h_name, sizeof(msg->value.buf));
	priv_send_back(msg);
}

void
priv_open_readonly(struct priv_msg *msg)
{
	char* authorized[] = {
		"/proc/sys/net/ipv4/ip_forward",
		NULL
	};
	char **f;
	int fd;

	for (f=authorized; *f != NULL; f++) {
		if (strncmp(msg->value.buf, *f,
			sizeof(msg->value.buf)) == 0)
			continue;
	}
	msg->value.buf[sizeof(msg->value.buf) - 1] = '\0';
	if (f == NULL) {
		LLOG_WARNX("not authorized to open %s", msg->value.buf);
		msg->value.integer = -1;
		priv_send_back(msg);
		return;
	}
	if ((fd = open(*f, 0)) == -1) {
		msg->value.integer = -1;
		priv_send_back(msg);
		return;
	}
	msg->value.integer = fd;
	priv_send_back(msg);
	priv_send_fd(fd);
	close(fd);
}

struct dispatch_actions {
	int				msg;
	void(*function)(struct priv_msg *);
};

struct dispatch_actions actions[] = {
	{PRIV_FORK, priv_fork_daemon},
	{PRIV_CREATE_CTL_SOCKET, priv_create_ctl_socket},
	{PRIV_DELETE_CTL_SOCKET, priv_delete_ctl_socket},
	{PRIV_GET_HOSTNAME, priv_get_hostname},
	{PRIV_OPEN, priv_open_readonly},
	{0, NULL}
};

/* Main loop, run as root */
void
priv_loop()
{
	struct priv_msg msg;
	struct dispatch_actions *a;

	while (read(remote, &msg, sizeof(struct priv_msg)) ==
	    sizeof(struct priv_msg)) {
		for (a = actions; a->function != NULL; a++) {
			if (msg.msg == a->msg) {
				a->function(&msg);
				break;
			}
		}
		if (a->function == NULL)
			fatal("bogus message received");
	}
	/* Should never be there */
}

void
priv_exit()
{
	int status;
	int rc;
	if ((rc = waitpid(monitored, &status, WNOHANG)) == 0) {
		LLOG_DEBUG("killing child");
		kill(monitored, SIGTERM);
	}
	if ((rc = waitpid(monitored, &status, WNOHANG)) == -1)
		_exit(0);
	LLOG_DEBUG("waiting for child %d to terminate", monitored);
}

void
priv_shutdown(int sig)
{
	LLOG_DEBUG("received signal %d, exiting", sig);
	priv_exit();
}

/* Initialization */
void
#ifdef USE_SNMP
priv_init(int snmp)
#else
priv_init()
#endif
{
	int pair[2];
	struct passwd *user;
	uid_t uid;
	struct group *group;
	gid_t gid;

	/* Create socket pair */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
		fatal("unable to create socket pair for privilege separation");

	/* Get users */
	if ((user = getpwnam(PRIVSEP_USER)) == NULL)
		fatal("no " PRIVSEP_USER " user for privilege separation");
	uid = user->pw_uid;
	if ((group = getgrnam(PRIVSEP_GROUP)) == NULL)
		fatal("no " PRIVSEP_GROUP " group for privilege separation");
	gid = group->gr_gid;

	/* Spawn off monitor */
	if ((monitored = fork()) < 0)
		fatal("unable to fork monitor");
	switch (monitored) {
	case 0:
		/* We are in the children, drop privileges */
		if (chroot(PRIVSEP_CHROOT) == -1)
			fatal("unable to chroot");
		if ((setgid(gid) == -1) || (setuid(uid) == -1))
			fatal("unable to drop privileges");
		remote = pair[0];
		close(pair[1]);
		break;
	default:
		/* We are in the monitor */
		remote = pair[1];
		close(pair[0]);
		if (atexit(priv_exit) != 0)
			fatal("unable to set exit function");
		signal(SIGHUP, priv_shutdown);
		signal(SIGTERM, priv_shutdown);
		signal(SIGINT, priv_shutdown);
		signal(SIGCHLD, priv_shutdown);
		priv_loop();
		exit(0);
	}
	
}
