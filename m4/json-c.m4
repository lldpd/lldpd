#
# lldp_CHECK_JSONC
#

AC_DEFUN([lldp_CHECK_JSONC], [
 if test x"$with_json" = x"auto" -o x"$with_json" = x"json-c"; then
   PKG_CHECK_MODULES([JSONC], [json-c], [
     AC_SUBST([JSONC_LIBS])
     AC_SUBST([JSONC_CFLAGS])
     AC_DEFINE_UNQUOTED([USE_JSON], 1, [Define to indicate to enable JSON support])
     AC_DEFINE_UNQUOTED([USE_JSONC], 1, [Define to indicate to enable JSON via json-c support])
     with_json=json-c
   ],[
     PKG_CHECK_MODULES([JSONC], [json], [
       AC_SUBST([JSONC_LIBS])
       AC_SUBST([JSONC_CFLAGS])
       AC_DEFINE_UNQUOTED([USE_JSON], 1, [Define to indicate to enable JSON support])
       AC_DEFINE_UNQUOTED([USE_JSONC], 1, [Define to indicate to enable JSON via json-c support])
       with_json=json-c
     ],[
       if test x"$with_json" = x"json-c"; then
         AC_MSG_ERROR([*** unable to find json-c])
       fi
       with_json=no
     ])
   ])
 fi
])
