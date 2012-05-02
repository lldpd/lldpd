#
# lldp_CHECK_XML2
#


AC_DEFUN([lldp_CHECK_XML2], [
   PKG_CHECK_MODULES([XML2], [libxml-2.0], [],
   [AC_MSG_CHECKING([presence of xml2-config])
    AC_PATH_TOOL([XML2_CONFIG], [xml2-config], [no])
    if test x"$XML2_CONFIG" = x"no"; then
      AC_MSG_ERROR([*** unable to find xml2-config])
    fi
    XML2_LIBS=`${XML2_CONFIG} --libs`
    XML2_CFLAGS=`${XML2_CONFIG} --cflags`
    AC_MSG_RESULT([found!])
   ])

   AC_SUBST([XML2_LIBS])
   AC_SUBST([XML2_CFLAGS])
   AC_DEFINE_UNQUOTED([USE_XML], 1, [Define to indicate to enable XML support])
])
