AM_CFLAGS = -I $(top_srcdir)/include

sbin_PROGRAMS = lldpcli
dist_man_MANS = lldpcli.8 lldpctl.8

install-exec-local: lldpcli
	cd $(DESTDIR)$(sbindir) && $(LN_S) lldpcli lldpctl
uninstall-local:
	cd $(DESTDIR)$(sbindir) && rm -f lldpctl

lldpcli_SOURCES  = client.h lldpcli.c display.c actions.c \
	commands.c show.c \
	misc.c \
	writer.h text_writer.c kv_writer.c
lldpcli_LDADD    = \
	$(top_builddir)/src/libcommon-daemon-client.la \
	$(top_builddir)/src/lib/liblldpctl.la \
	@EDITLINE_LIBS@
lldpcli_CFLAGS   = $(AM_CFLAGS) @EDITLINE_CFLAGS@

if USE_XML
lldpcli_SOURCES += xml_writer.c
lldpcli_CFLAGS  += @XML2_CFLAGS@
lldpcli_LDADD   += @XML2_LIBS@
endif

if USE_JSON
lldpcli_SOURCES += json_writer.c
lldpcli_CFLAGS  += @JANSSON_CFLAGS@
lldpcli_LDADD   += @JANSSON_LIBS@
endif
