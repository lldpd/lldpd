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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ctl.h"
#include "marshal.h"
#include "log.h"
#include "compat/compat.h"

#define UNIX_PATH_MAX	108

/**
 * Create a new listening Unix socket for control protocol.
 *
 * @param name The name of the Unix socket.
 * @return The socket when successful, -1 otherwise.
 */
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

/**
 * Connect to the control Unix socket.
 *
 * @param name The name of the Unix socket.
 * @return The socket when successful, -1 otherwise.
 */
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
		LLOG_WARN("unable to connect to socket %s", name);
		errno = rc; return -1;
	}
	return s;
}

/**
 * Remove the control Unix socket.
 *
 * @param name The name of the Unix socket.
 */
void
ctl_cleanup(char *name)
{
	if (unlink(name) == -1)
		LLOG_WARN("unable to unlink %s", name);
}

/** Header for the control protocol.
 *
 * The protocol is pretty simple. We send a single message containing the
 * provided message type with the message length, followed by the message
 * content.
 */
struct hmsg_header {
	enum hmsg_type type;
	size_t         len;
};

/**
 * Send a message with the control protocol.
 *
 * @param fd   The file descriptor that should be used.
 * @param type The message type to be sent.
 * @param t    The buffer containing the message content. Can be @c NULL if the
 *             message is empty.
 * @param len  The length of the buffer containing the message content.
 * @return     The number of bytes written or -1 in case of error.
 */
int
ctl_msg_send(int fd, enum hmsg_type type, void *t, size_t len)
{
	struct iovec iov[2];
	struct hmsg_header hdr;
	memset(&hdr, 0, sizeof(struct hmsg_header));
	hdr.type = type;
	hdr.len  = len;
	iov[0].iov_base = &hdr;
	iov[0].iov_len  = sizeof(struct hmsg_header);
	iov[1].iov_base = t;
	iov[1].iov_len  = len;
	return writev(fd, iov, t?2:1);
}

/**
 * Receive a message with the control protocol.
 *
 * @param fd        The file descriptor that should be used.
 * @param type[out] The type of the received message.
 * @param t         The buffer containing the message content.
 * @return  The size of the returned buffer. 0 if the message is empty. -1 if
 *          there is an error.
 */
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

/**
 * Serialize and "send" a structure through the control protocol.
 *
 * This function does not really send the message but outputs it to a buffer.
 *
 * @param output_buffer A pointer to a buffer to which the message will be
 *                      appended. Can be @c NULL. In this case, the buffer will
 *                      be allocated.
 * @param output_len[in,out] The length of the provided buffer. Will be updated
 *                           with the new length
 * @param type  The type of message we want to send.
 * @param t     The structure to be serialized and sent.
 * @param mi    The appropriate marshal structure for serialization.
 * @return -1 in case of failure, 0 in case of success.
 */
int
ctl_msg_send_unserialized(uint8_t **output_buffer, size_t *output_len,
    enum hmsg_type type,
    void *t, struct marshal_info *mi)
{
	struct hmsg_header hdr;
	size_t len = 0, newlen;
	void *buffer = NULL;

	if (t) {
		len = marshal_serialize_(mi, t, &buffer, 0, NULL, 0);
		if (len <= 0) {
			LLOG_WARNX("unable to serialize data");
			return -1;
		}
	}

	newlen = len + sizeof(struct hmsg_header);

	if (*output_buffer == NULL) {
		*output_len = 0;
		if ((*output_buffer = malloc(newlen)) == NULL) {
			LLOG_WARN("no memory available");
			free(buffer);
			return -1;
		}
	} else {
		void *new = realloc(*output_buffer, *output_len + newlen);
		if (new == NULL) {
			LLOG_WARN("no memory available");
			free(buffer);
			return -1;
		}
		*output_buffer = new;
	}
	memset(&hdr, 0, sizeof(struct hmsg_header));
	hdr.type = type;
	hdr.len  = len;
	memcpy(*output_buffer + *output_len, &hdr, sizeof(struct hmsg_header));
	if (t)
		memcpy(*output_buffer + *output_len + sizeof(struct hmsg_header), buffer, len);
	*output_len += newlen;
	free(buffer);
	return 0;
}

/**
 * "Receive" and unserialize a structure through the control protocol.
 *
 * Like @c ctl_msg_send_unserialized(), this function uses buffer to receive the
 * incoming message.
 *
 * @param input_buffer[in,out] The buffer with the incoming message. Will be
 *                             updated once the message has been unserialized to
 *                             point to the remaining of the message or will be
 *                             freed if all the buffer has been consumed. Can be
 *                             @c NULL.
 * @param input_len[in,out]    The length of the provided buffer. Will be updated
 *                             to the length of remaining data once the message
 *                             has been unserialized.
 * @param expected_type        The expected message type.
 * @param t[out]               Will contain a pointer to the unserialized structure.
 *                             Can be @c NULL if we don't want to store the
 *                             answer.
 * @param mi                   The appropriate marshal structure for unserialization.
 *
 * @return -1 in case of error, 0 in case of success and the number of bytes we
 *         request to complete unserialization.
 */
size_t
ctl_msg_recv_unserialized(uint8_t **input_buffer, size_t *input_len,
    enum hmsg_type expected_type,
    void **t, struct marshal_info *mi)
{
	struct hmsg_header *hdr;
	int rc = -1;

	if (*input_buffer == NULL ||
	    *input_len < sizeof(struct hmsg_header)) {
		/* Not enough data. */
		return sizeof(struct hmsg_header) - *input_len;
	}
	hdr = (struct hmsg_header *)*input_buffer;
	if (hdr->len > (1<<15)) {
		LLOG_WARNX("message received is too large");
		/* We discard the whole buffer */
		free(*input_buffer);
		*input_buffer = NULL;
		*input_len = 0;
		return -1;
	}
	if (*input_len < sizeof(struct hmsg_header) + hdr->len) {
		/* Not enough data. */
		return sizeof(struct hmsg_header) + hdr->len - *input_len;
	}
	if (hdr->type != expected_type) {
		LLOG_WARNX("incorrect received message type (expected: %d, received: %d)",
		    expected_type, hdr->type);
		goto end;
	}

	if (t && !hdr->len) {
		LLOG_WARNX("no payload available in answer");
		goto end;
	}
	if (t) {
		/* We have data to unserialize. */
		if (marshal_unserialize_(mi, *input_buffer + sizeof(struct hmsg_header),
			hdr->len, t, NULL, 0, 0) <= 0) {
			LLOG_WARNX("unable to deserialize received data");
			goto end;
		}
	}

	rc = 0;
end:
	/* Discard input buffer */
	*input_len -= sizeof(struct hmsg_header) + hdr->len;
	if (*input_len == 0) {
		free(*input_buffer);
		*input_buffer = NULL;
	} else
		memmove(input_buffer, input_buffer + sizeof(struct hmsg_header) + hdr->len,
		    *input_len);
	return rc;
}
