AM_CFLAGS = -I $(top_srcdir)/include

lib_LTLIBRARIES = liblldpctl.la
include_HEADERS = lldpctl.h

noinst_LTLIBRARIES = libfixedpoint.la
libfixedpoint_la_SOURCES = fixedpoint.h fixedpoint.c

liblldpctl_la_SOURCES = lldpctl.h private.h errors.c connection.c atom.c atom-private.c
liblldpctl_la_LIBADD  = $(top_builddir)/src/libcommon-daemon-lib.la libfixedpoint.la
liblldpctl_la_LDFLAGS = -export-symbols-regex '^lldpctl_' -version-info 8:0:4

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91

pkgconfig_DATA = lldpctl.pc

TEMPLATES  = lldpctl.pc
EXTRA_DIST = lldpctl.pc.in
CLEANFILES = $(TEMPLATES)
lldpctl.pc: lldpctl.pc.in
include $(top_srcdir)/edit.am
