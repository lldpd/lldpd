#
# lldp_CHECK_XML2
#


AC_DEFUN([lldp_CHECK_XML2], [
   AC_PATH_TOOL([XML2_CONFIG], [xml2-config], [no])
   if test x"$XML2_CONFIG" = x"no"; then
      AC_MSG_ERROR([*** unable to find xml2-config])
   fi
   XML2_LIBS=`${XML2_CONFIG} --libs`
   XML2_CFLAGS=`${XML2_CONFIG} --cflags`

   _save_flags="$CFLAGS"
   CFLAGS="$CFLAGS ${XML2_CFLAGS}"
   AC_MSG_CHECKING([whether C compiler supports flag "${XML2_CFLAGS}" from libxml2])
   AC_LINK_IFELSE([AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])],[AC_MSG_RESULT(yes)],[
AC_MSG_RESULT(no)
AC_MSG_ERROR([*** incorrect CFLAGS from xml2-config])])
   AC_CHECK_LIB([xml2], [xmlNewTextWriterDoc], [:],
       [AC_MSG_ERROR([*** unable to use xml2])], ${XML2_LIBS})
   AC_SUBST([XML2_LIBS])
   AC_SUBST([XML2_CFLAGS])
   AC_DEFINE_UNQUOTED([USE_XML], 1, [Define to indicate to enable XML support])

   CFLAGS="$_save_flags"
])
