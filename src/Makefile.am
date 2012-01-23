sbin_PROGRAMS = lldpd lldpctl
noinst_LTLIBRARIES = liblldpd.la libcommon.la

## Shared by all executables
libcommon_la_SOURCES = log.c ctl.c marshal.c marshal.h lldpd.h lldp.h cdp.h compat.h sonmp.h edp.h
libcommon_la_LIBADD = @LTLIBOBJS@ 

## Used for lldpd and tests
liblldpd_la_SOURCES = frame.h frame.c lldpd.c lldp.c cdp.c sonmp.c edp.c \
	interfaces.c client.c priv.c privsep_fdpass.c dmi.c ctl-server.c
liblldpd_la_LIBADD = libcommon.la

## lldpd
lldpd_SOURCES = main.c
lldpd_LDADD = liblldpd.la

## lldpctl
lldpctl_SOURCES = lldpctl.h lldpctl.c display.c writer.h text_writer.c kv_writer.c
lldpctl_LDADD = libcommon.la

## With SNMP...
if USE_SNMP
liblldpd_la_SOURCES += agent.c agent_priv.c agent.h
liblldpd_la_CFLAGS = @NETSNMP_CFLAGS@
lldpd_LDADD += @NETSNMP_LIBS@
endif

if USE_XML
lldpctl_SOURCES += xml_writer.c
lldpctl_CFLAGS = @XML2_CFLAGS@
lldpctl_LDADD  += @XML2_LIBS@
endif


