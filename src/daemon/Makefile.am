sbin_PROGRAMS = lldpd

noinst_LTLIBRARIES = liblldpd.la

## Convenience library for lldpd and tests
liblldpd_la_SOURCES  = frame.h frame.c lldpd.c lldp.c cdp.c sonmp.c edp.c
liblldpd_la_SOURCES += interfaces.c client.c priv.c privsep_fdpass.c dmi.c
liblldpd_la_SOURCES += event.c
liblldpd_la_CFLAGS   = @LIBEVENT_CFLAGS@
liblldpd_la_LIBADD   = $(top_builddir)/src/libcommon-daemon-client.la $(top_builddir)/src/libcommon-daemon-lib.la @LIBEVENT_LIBS@

# Add SNMP support if needed
if USE_SNMP
liblldpd_la_SOURCES += agent.c agent_priv.c agent.h
liblldpd_la_CFLAGS  += @NETSNMP_CFLAGS@
liblldpd_la_LIBADD  += @NETSNMP_LIBS@
endif

## lldpd
lldpd_SOURCES = main.c
lldpd_LDADD   = liblldpd.la @LIBEVENT_LDFLAGS@

## libevent
if LIBEVENT_EMBEDDED
event.c: $(top_builddir)/libevent/libevent.la
$(top_builddir)/libevent/libevent.la: $(top_srcdir)/libevent/*.c $(top_srcdir)/libevent/*.h
	(cd $(top_builddir)/libevent && $(MAKE))
endif
