/* -*- mode: c; c-file-style: "openbsd" -*- */

#include <stdlib.h>
#include <syslog.h>
#include "compat.h"

/* vsyslog() doesn't exist on HP-UX */
void
vsyslog(int facility, const char *format, va_list ap) {
	char *msg = NULL;
	vasprintf(&msg, format, ap);
	if (!msg) return;
	syslog(facility, "%s", msg);
	free(msg);
}
