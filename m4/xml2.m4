#
# lldp_CHECK_XML2
#


AC_DEFUN([lldp_CHECK_XML2], [
  AS_IF([test x"$with_xml" != x"no"], [
   PKG_CHECK_MODULES([libxml2], [libxml-2.0], [
    dnl Found through pkg-config
    AC_DEFINE_UNQUOTED([USE_XML], 1, [Define to indicate to enable XML support])
    with_xml=yes
   ],[
    dnl Fallback to xml2-config
    AC_PATH_TOOL([XML2_CONFIG], [xml2-config], [no])
    AS_IF([test x"$XML2_CONFIG" = x"no"], [
      dnl No luck
      AS_IF([test x"$with_xml" = x"yes"], [
         AC_MSG_FAILURE([*** no libxml2 support found])
      ])
      with_xml=no
    ], [
      dnl Check that it's working as expected
      libxml2_LIBS=`${XML2_CONFIG} --libs`
      libxml2_CFLAGS=`${XML2_CONFIG} --cflags`

      _save_flags="$CFLAGS"
      _save_libs="$LIBS"
      CFLAGS="$CFLAGS ${libxml2_CFLAGS}"
      LIBS="$LIBS ${libxml2_LIBS}"
      AC_MSG_CHECKING([whether libxml-2 work as expected])
      AC_LINK_IFELSE([AC_LANG_PROGRAM([
@%:@include <libxml/encoding.h>
@%:@include <libxml/xmlwriter.h>
],[
	xmlDocPtr doc;
	xmlTextWriterPtr xw = xmlNewTextWriterDoc(&doc, 0);
        return (xw != NULL);
])],[
        AC_MSG_RESULT(yes)
        AC_SUBST([libxml2_LIBS])
        AC_SUBST([libxml2_CFLAGS])
        AC_DEFINE_UNQUOTED([USE_XML], 1, [Define to indicate to enable XML support])
        with_xml=yes
      ],[
        AC_MSG_RESULT(no)
        AS_IF([test x"$with_xml" = x"yes"], [
            AC_MSG_FAILURE([*** libxml2 not working as expected])
        ])
        with_xml=no
      ])
      CFLAGS="$_save_flags"
      LIBS="$_save_libs"
    ])
   ])
  ])
])
