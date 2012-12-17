#
# lldp_CHECK_JANSSON
#

AC_DEFUN([lldp_CHECK_JANSSON], [
   PKG_CHECK_MODULES([JANSSON], [jansson >= 2], [],
      [AC_MSG_ERROR([*** unable to find libjansson])])

   AC_SUBST([JANSSON_LIBS])
   AC_SUBST([JANSSON_CFLAGS])
   AC_DEFINE_UNQUOTED([USE_JSON], 1, [Define to indicate to enable JSON support])
])
