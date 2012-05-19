#
# lldp_CHECK_LIBEVENT
#

AC_DEFUN([lldp_CHECK_LIBEVENT], [
  _save_LIBS="$LIBS"
  _save_CFLAGS="$CFLAGS"

  # First, try with pkg-config
  PKG_CHECK_MODULES([LIBEVENT], [libevent >= 2.0.5], [], [
    # No appropriate version, let's use the shipped copy
    AC_MSG_NOTICE([using shipped libevent])
    LIBEVENT_CFLAGS="-I\$(top_srcdir)/libevent/include -I\$(top_builddir)/libevent/include"
    LIBEVENT_LDFLAGS="\$(top_builddir)/libevent/libevent.la"
  ])

  # Override configure arguments
  ac_configure_args="$ac_configure_args --disable-libevent-regress --disable-thread-support --disable-shared --enable-static"
  AC_CONFIG_SUBDIRS([libevent])
  AM_CONDITIONAL([LIBEVENT_EMBEDDED], [test x"$LIBEVENT_LDFLAGS" != x])
  AC_SUBST([LIBEVENT_LIBS])
  AC_SUBST([LIBEVENT_CFLAGS])
  AC_SUBST([LIBEVENT_LDFLAGS])
])
