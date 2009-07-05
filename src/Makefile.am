sbin_PROGRAMS = lldpd lldpctl
noinst_LTLIBRARIES = liblldpd.la

COMMON = log.c ctl.c lldpd.h lldp.h cdp.h compat.h sonmp.h edp.h
liblldpd_la_SOURCES = frame.h frame.c lldpd.c lldp.c cdp.c sonmp.c edp.c interfaces.c client.c priv.c privsep_fdpass.c dmi.c $(COMMON)
lldpctl_SOURCES = lldpctl.c $(COMMON)

liblldpd_la_LIBADD = @LTLIBOBJS@
lldpctl_LDADD = @LIBOBJS@
lldpctl_CFLAGS = -DCLIENT_ONLY

lldpd_SOURCES = main.c
lldpd_LDADD = liblldpd.la

if USE_SNMP
liblldpd_la_SOURCES += agent.c agent_priv.c
lldpd_LDADD += @NETSNMP_LIB@
endif

