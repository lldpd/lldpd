#
# lldp_CHECK_JANSSON
#

AC_DEFUN([lldp_CHECK_JANSSON], [
 if test x"$with_json" = x"auto" -o x"$with_json" = x"jansson"; then
   PKG_CHECK_MODULES([JANSSON], [jansson >= 2], [
     AC_SUBST([JANSSON_LIBS])
     AC_SUBST([JANSSON_CFLAGS])
     AC_DEFINE_UNQUOTED([USE_JSON], 1, [Define to indicate to enable JSON support])
     AC_DEFINE_UNQUOTED([USE_JANSSON], 1, [Define to indicate to enable JSON support through jansson])
     with_json=jansson
   ],[
     if test x"$with_json" = x"jansson"; then
       AC_MSG_ERROR([*** unable to find libjansson])
     fi
     with_json=no
   ])
 fi
])
