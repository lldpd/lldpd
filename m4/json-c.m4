#
# lldp_CHECK_JSONC
#

AC_DEFUN([lldp_CHECK_JSONC], [
   PKG_CHECK_MODULES([JSONC], [json-c >= 0], [],
      [AC_MSG_ERROR([*** unable to find json-c])])

   AC_SUBST([JSONC_LIBS])
   AC_SUBST([JSONC_CFLAGS])
   AC_DEFINE_UNQUOTED([USE_JSON], 1, [Define to indicate to enable JSON support])
   AC_DEFINE_UNQUOTED([USE_JSONC], 1, [Define to indicate to enable JSON via json-c support])
])
