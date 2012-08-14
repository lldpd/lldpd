noinst_LTLIBRARIES = libcommon-daemon-lib.la libcommon-daemon-client.la
include_HEADERS    = lldp-const.h

libcommon_daemon_lib_la_SOURCES = log.c log.h marshal.c marshal.h ctl.c ctl.h lldpd-structs.c lldpd-structs.h lldpd-const.h
libcommon_daemon_lib_la_LIBADD  = compat/libcompat.la

libcommon_daemon_client_la_SOURCES = log.c log.h lldpd-const.h
libcommon_daemon_client_la_LIBADD  = compat/libcompat.la
