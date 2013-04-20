AM_CFLAGS = -I $(top_srcdir)/include

lib_LTLIBRARIES = liblldpctl.la
include_HEADERS = lldpctl.h

liblldpctl_la_SOURCES = lldpctl.h private.h errors.c connection.c atom.c atom-private.c
liblldpctl_la_LIBADD  = $(top_builddir)/src/libcommon-daemon-lib.la
liblldpctl_la_LDFLAGS = -export-symbols-regex '^lldpctl_' -version-info 3:0:3

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = lldpctl.pc
