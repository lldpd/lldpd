AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)

sbin_PROGRAMS = lldpcli
man_MANS = lldpcli.8
dist_man_MANS = lldpctl.8

install-exec-local: lldpcli
	cd $(DESTDIR)$(sbindir) && rm -f lldpctl
	cd $(DESTDIR)$(sbindir) && $(LN_S) lldpcli lldpctl
uninstall-local:
	cd $(DESTDIR)$(sbindir) && rm -f lldpctl

lldpcli_SOURCES  = client.h lldpcli.c display.c \
	conf.c conf-med.c conf-dot3.c conf-power.c \
	conf-lldp.c conf-system.c \
	commands.c show.c \
	misc.c tokenizer.c \
	writer.h text_writer.c kv_writer.c
lldpcli_LDADD    = \
	$(top_builddir)/src/libcommon-daemon-client.la \
	$(top_builddir)/src/lib/liblldpctl.la \
	@READLINE_LIBS@
lldpcli_CFLAGS   = $(AM_CFLAGS)

if USE_XML
lldpcli_SOURCES += xml_writer.c
lldpcli_CFLAGS  += @XML2_CFLAGS@
lldpcli_LDADD   += @XML2_LIBS@
endif

if USE_JANSSON
lldpcli_SOURCES += jansson_writer.c
lldpcli_CFLAGS  += @JANSSON_CFLAGS@
lldpcli_LDADD   += @JANSSON_LIBS@
endif

if USE_JSONC
lldpcli_SOURCES += jsonc_writer.c
lldpcli_CFLAGS  += @JSONC_CFLAGS@
lldpcli_LDADD   += @JSONC_LIBS@
endif

# Completions
bashcompletiondir = $(sysconfdir)/bash_completion.d
dist_bashcompletion_DATA = lldpcli.bash-completion
zshcompletiondir = $(datadir)/zsh/vendor-completions
dist_zshcompletion_DATA = _lldpcli

# Default configuration
lldpdconfdir = $(sysconfdir)/lldpd.d
dist_lldpdconf_DATA = README.conf

TEMPLATES  = lldpcli.8
EXTRA_DIST = lldpcli.8.in
CLEANFILES = $(TEMPLATES)
lldpcli.8: lldpcli.8.in
include $(top_srcdir)/edit.am
