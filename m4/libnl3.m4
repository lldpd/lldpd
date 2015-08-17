#
# lldp_CHECK_LIBNL
#

AC_DEFUN([lldp_CHECK_LIBNL], [
 # Do we require embedded libnl?
 if test x"$os" = x"Linux"; then
  AC_ARG_WITH([embedded-libnl],
    AS_HELP_STRING(
      [--with-embedded-libnl],
      [Use embedded libnl @<:@default=auto@:>@]
  ), [], [with_embedded_libnl=auto])
  if test x"$with_embedded_libnl" = x"yes"; then
     LIBNL_EMBEDDED=1
  else
    # Check with pkg-config (3.2.7 is needed for nl_cache_mngr_alloc)
    PKG_CHECK_MODULES([LIBNL], [libnl-3.0 >= 3.2.7 libnl-route-3.0 >= 3.2.7], [], [
      # No appropriate version, let's use the shipped copy if possible
      if test x"$with_embedded_libnl" = x"auto"; then
        AC_MSG_NOTICE([using shipped libnl])
        LIBNL_EMBEDDED=1
      else
        AC_MSG_ERROR([*** libnl not found])
      fi
    ])
  fi

  if test x"$LIBNL_EMBEDDED" != x; then
    unset LIBNL_LIBS
    LIBNL_CFLAGS="-I\$(top_srcdir)/libnl/include -I\$(top_builddir)/libnl/include"
    LIBNL_LDFLAGS="\$(top_builddir)/libnl/lib/libnl-3.la \$(top_builddir)/libnl/lib/libnl-route-3.la"
  fi

  # Call ./configure in libnl. Need it for make dist...
  libnl_configure_args="$libnl_configure_args --disable-pthreads"
  libnl_configure_args="$libnl_configure_args --disable-cli"
  libnl_configure_args="$libnl_configure_args --disable-debug"
  libnl_configure_args="$libnl_configure_args --disable-shared"
  libnl_configure_args="$libnl_configure_args --with-pic"
  libnl_configure_args="$libnl_configure_args --enable-static"
  lldp_CONFIG_SUBDIRS([libnl], [$libnl_configure_args])
 fi

 AM_CONDITIONAL([LIBNL_EMBEDDED], [test x"$LIBNL_EMBEDDED" != x])
 AC_SUBST([LIBNL_LIBS])
 AC_SUBST([LIBNL_CFLAGS])
 AC_SUBST([LIBNL_LDFLAGS])
])
