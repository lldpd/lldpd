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

#include "lldpd.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int
ctl_create(char *name)
{
	int s;
	struct sockaddr_un su;
	int rc;

	if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	su.sun_family = AF_UNIX;
	strlcpy(su.sun_path, name, UNIX_PATH_MAX);
	if (bind(s, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
		rc = errno; close(s); errno = rc;
		return -1;
	}
	if (listen(s, 5) == -1) {
		rc = errno; close(s); errno = rc;
		return -1;
	}
	return s;
}

int
ctl_connect(char *name)
{
	int s;
	struct sockaddr_un su;
	int rc;

	if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	su.sun_family = AF_UNIX;
	strlcpy(su.sun_path, name, UNIX_PATH_MAX);
	if (connect(s, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
		rc = errno;
		LLOG_WARN("unable to connect to socket " LLDPD_CTL_SOCKET);
		errno = rc; return -1;
	}
	return s;
}

struct hmsg_header {
	enum hmsg_type type;
	size_t         len;
};

/* The protocol is pretty simple. We send a single message containing the
 * provided message type with the message length, followed by the message
 * content. It is expected the message content to be serialized. */
int
ctl_msg_send(int fd, enum hmsg_type type, void *t, size_t len)
{
	struct iovec iov[2];
	struct hmsg_header hdr;
	hdr.type = type;
	hdr.len  = len;
	iov[0].iov_base = &hdr;
	iov[0].iov_len  = sizeof(struct hmsg_header);
	iov[1].iov_base = t;
	iov[1].iov_len  = len;
	return writev(fd, iov, t?2:1);
}

int
ctl_msg_recv(int fd, enum hmsg_type *type, void **t)
{
	int n, flags = -1;
	struct hmsg_header hdr;
	*type = NONE; *t = NULL;
	/* First, we read the header to know the size of the message */
	if ((n = read(fd, &hdr, sizeof(struct hmsg_header))) == -1) {
		LLOG_WARN("unable to read message header");
		return -1;
	}
	if (n == 0)
		/* Remote closed the connection. */
		return -1;
	if (n < sizeof(struct hmsg_header)) {
		LLOG_WARNX("message received too short (%d)", n);
		goto recv_error;
	}
	if (hdr.len > (1<<15)) {
		LLOG_WARNX("message received is too large");
		goto recv_error;
	}
	if (hdr.len == 0) {
		/* No answer */
		*type = hdr.type;
		return 0;
	}
	/* Now, we read the remaining message. We need to use non-blocking stuff
	 * just in case the message was truncated. */
	if ((*t = malloc(hdr.len)) == NULL) {
		LLOG_WARNX("not enough space available for incoming message");
		goto recv_error;
	}
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		LLOG_WARN("unable to set socket access mode to non blocking");
		goto recv_error;
	}
	if ((n = read(fd, *t, hdr.len)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LLOG_WARNX("message seems truncated");
			goto recv_error;
		}
		LLOG_WARN("unable to read incoming request");
		goto recv_error;
	}
	if (n != hdr.len) {
		LLOG_WARNX("received message is too short (%d < %zu)",
			   n, hdr.len);
		goto recv_error;
	}
	fcntl(fd, F_SETFL, flags); /* No error check */
	*type = hdr.type;
	return hdr.len;
recv_error:
	free(*t); *t = NULL;
	if (flags != -1) fcntl(fd, F_SETFL, flags);
	return -1;
}

int
ctl_msg_send_recv(int fd,
    enum hmsg_type type,
    void *input, struct marshal_info *input_mi,
    void **output, struct marshal_info *output_mi)
{
	int n, input_len = 0;
	void *input_buffer = NULL;
	void *serialized = NULL;
	enum hmsg_type received_type;

	/* Serialize */
	if (input) {
		input_len = marshal_serialize_(input_mi, input, &input_buffer, 0, NULL, 0);
		if (input_len <= 0) {
			LLOG_WARNX("unable to serialize input data");
			return -1;
		}
	}
	/* Send request */
	if (ctl_msg_send(fd, type, input_buffer, input_len) == -1) {
		LLOG_WARN("unable to send request");
		goto send_recv_error;
	}
	free(input_buffer); input_buffer = NULL;
	/* Receive answer */
	if ((n = ctl_msg_recv(fd, &received_type, &serialized)) == -1)
		goto send_recv_error;
	/* Check type */
	if (received_type != type) {
		LLOG_WARNX("incorrect received message type (expected: %d, received: %d)",
		    type, received_type);
		goto send_recv_error;
	}
	/* Unserialize */
	if (output == NULL) {
		free(serialized);
		return 0;
	}
	if (n == 0) {
		LLOG_WARNX("no payload available in answer");
		goto send_recv_error;
	}
	if (marshal_unserialize_(output_mi, serialized, n, output, NULL, 0, 0) <= 0) {
		LLOG_WARNX("unable to deserialize received data");
		goto send_recv_error;
	}
	/* All done. */
	return 0;
send_recv_error:
	free(serialized);
	free(input_buffer);
	return -1;
}

void
ctl_cleanup(char *name)
{
	if (unlink(name) == -1)
		LLOG_WARN("unable to unlink %s", name);
}
