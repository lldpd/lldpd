AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS)

lib_LTLIBRARIES = liblldpctl.la
include_HEADERS = lldpctl.h

noinst_LTLIBRARIES = libfixedpoint.la
libfixedpoint_la_SOURCES = fixedpoint.h fixedpoint.c

liblldpctl_la_SOURCES = \
	lldpctl.h atom.h errors.c connection.c atom.c helpers.c helpers.h \
	atoms/config.c atoms/dot1.c atoms/dot3.c \
	atoms/interface.c atoms/med.c atoms/mgmt.c atoms/port.c \
	atoms/custom.c atoms/chassis.c
liblldpctl_la_LIBADD  = $(top_builddir)/src/libcommon-daemon-lib.la libfixedpoint.la

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   https://www.sourceware.org/autobook/autobook/autobook_61.html#Library-Versioning
#
# -version-number could be computed from -version-info, mostly major
# is `current` - `age`, minor is `age` and revision is `revision' and
# major.minor should be used when updaing lldpctl.map.
liblldpctl_la_LDFLAGS = $(AM_LDFLAGS) -version-info 11:0:7
liblldpctl_la_DEPENDENCIES = libfixedpoint.la

if HAVE_LD_VERSION_SCRIPT
liblldpctl_la_DEPENDENCIES += lldpctl.map
liblldpctl_la_LDFLAGS += -Wl,--version-script=$(srcdir)/lldpctl.map
else
liblldpctl_la_LDFLAGS += -export-symbols-regex '^lldpctl_'
endif

pkgconfig_DATA = lldpctl.pc

TEMPLATES  = lldpctl.pc
EXTRA_DIST = lldpctl.pc.in lldpctl.map
CLEANFILES = $(TEMPLATES)
lldpctl.pc: lldpctl.pc.in
include $(top_srcdir)/edit.am
