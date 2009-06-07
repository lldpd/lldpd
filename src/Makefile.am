sbin_PROGRAMS = lldpd lldpctl

COMMON = log.c ctl.c lldpd.h lldp.h cdp.h compat.h sonmp.h edp.h
lldpd_SOURCES = frame.h frame.c lldpd.c lldp.c cdp.c sonmp.c edp.c interfaces.c client.c priv.c privsep_fdpass.c dmi.c $(COMMON)
lldpctl_SOURCES = lldpctl.c $(COMMON)

lldpd_LDADD = @LIBOBJS@
lldpctl_LDADD = @LIBOBJS@
lldpctl_CFLAGS = -DCLIENT_ONLY

if USE_SNMP
lldpd_SOURCES += agent.c agent_priv.c
lldpd_LDADD += @NETSNMP_LIB@
endif
