include doxygen.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS      = src/compat src src/daemon src/lib src/client man tests
EXTRA_DIST   = $(DX_CONFIG)
DIST_SUBDIRS = $(SUBDIRS) libevent

dist_doc_DATA = README.md NEWS

# Build changelog from git history
dist-hook: $(distdir)/ChangeLog
$(distdir)/ChangeLog:
	if test -d $(top_srcdir)/.git; then \
		prev=$$(git describe --tags --always --match [0-9]* 2> /dev/null) ; \
		for tag in $$(git tag | grep -E '^[0-9]+(\.[0-9]+){1,}$$' | sort -rn); do \
			if [ x"$$prev" = x ]; then prev=$$tag ; fi ; \
			if [ x"$$prev" = x"$$tag" ]; then continue; fi ; \
			echo "$$prev:" ; \
			echo "" ; \
			git log --pretty=' - %s' $$tag..$$prev ; \
			echo "" ; \
			prev=$$tag ; \
		done > $@ ; \
	fi

MOSTLYCLEANFILES = $(DX_CLEANFILES)
