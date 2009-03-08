#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(lldpd, 0.3.3, bernat@luffy.cx)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/lldpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_ARG_WITH(snmp,
  AC_HELP_STRING(
    [--with-snmp],
    [Enable the use of SNMP]
  ),
  [],
  [with_snmp=no]
)
AM_CONDITIONAL([USE_SNMP], [test "${with_snmp}" != "no"])

AC_ARG_WITH(privsep-user,
	AC_HELP_STRING([--with-privsep-user],
		       [Which user to use for privilege separation]),
	AC_DEFINE_UNQUOTED([PRIVSEP_USER], "$withval", [User for privilege separation]),
	AC_DEFINE_UNQUOTED([PRIVSEP_USER], "_lldpd", [User for privilege separation]))
AC_ARG_WITH(privsep-group,
	AC_HELP_STRING([--with-privsep-group],
		       [Which group to use for privilege separation]),
	AC_DEFINE_UNQUOTED([PRIVSEP_GROUP], "$withval", [Group for privilege separation]),
	AC_DEFINE_UNQUOTED([PRIVSEP_GROUP], "_lldpd", [Group for privilege separation]))
AC_ARG_WITH(privsep-chroot,
	AC_HELP_STRING([--with-privsep-chroot],
		       [Which directory to use to chroot lldpd]),
	AC_DEFINE_UNQUOTED([PRIVSEP_CHROOT], "$withval", [Chroot directory]),
	AC_DEFINE_UNQUOTED([PRIVSEP_CHROOT], "/var/run/lldpd", [Chroot directory]))

# Checks for header files.
AC_CHECK_DECLS([TAILQ_FIRST, TAILQ_NEXT, TAILQ_FOREACH, TAILQ_EMPTY],[],[],[[#include <sys/queue.h>]])
AC_CHECK_DECLS([SLIST_HEAD, SLIST_ENTRY, SLIST_INIT, SLIST_INSERT_HEAD],[],[],[[#include <sys/queue.h>]])
AC_CHECK_DECLS([SLIST_FIRST, SLIST_NEXT, SLIST_REMOVE_HEAD, SLIST_EMPTY],[],[],[[#include <sys/queue.h>]])
AC_CHECK_DECLS([PACKET_ORIGDEV],[],[],[[#include <linux/if_packet.h>]])
AC_CHECK_DECLS([ADVERTISED_2500baseX_Full, ADVERTISED_Pause, ADVERTISED_Asym_Pause],
					   [],[],[[#include <linux/ethtool.h>]])
AC_CHECK_DECLS([ETHERTYPE_VLAN],[],[],[[#include <net/ethernet.h>]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_CHECK_TYPES([int16_t, u_int16_t, int8_t, u_int8_t, int32_t, u_int32_t],[],[AC_MSG_ERROR([mandatory type not found])])
AC_CHECK_MEMBERS([netsnmp_tdomain.f_create_from_tstring_new],,,
	[
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_transport.h>
])

# Checks for library functions.
AC_REPLACE_FUNCS([strlcpy])

AC_PROG_GCC_TRADITIONAL

## NetSNMP
NETSNMP_CONFIG=No
if test "${with_snmp}" != "no"; then	
      AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], No)
fi
if test x"${NETSNMP_CONFIG}" != xNo; then
   NETSNMP_libs=`${NETSNMP_CONFIG} --agent-libs`
   
   AC_CHECK_LIB([netsnmp], [snmp_register_callback],
       AC_DEFINE_UNQUOTED([HAVE_NETSNMP], 1, [Define to indicate the Net-SNMP library])
       AC_DEFINE_UNQUOTED([USE_SNMP], 1, [Define to indicate to enable SNMP support]),
       [], ${NETSNMP_libs})

   if test "${ac_cv_lib_netsnmp_snmp_register_callback}" = "yes"; then
      AC_SUBST([NETSNMP_LIB],"${NETSNMP_libs}")
   fi
fi
if test "${with_snmp}" != "no"; then
   if test "${ac_cv_lib_netsnmp_snmp_register_callback}" != "yes"; then
         AC_MSG_NOTICE([***])
         AC_MSG_NOTICE([*** net-snmp libraries not found])
         AC_MSG_NOTICE([*** Either correct the installation, or run configure])
         AC_MSG_NOTICE([*** including --without-snmp])
	 exit 1
   fi
fi

# Options
# CDP
AC_ARG_ENABLE(cdp, AC_HELP_STRING([--enable-cdp],
		   [Enable Cisco Discovery Protocol]),
	      [enable_cdp=$enableval],[enable_cdp=yes])
AC_MSG_CHECKING(whether to enable CDP)
if test x$enable_cdp = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_CDP],, [Enable Cisco Discovery Protocol])
else
	AC_MSG_RESULT(no)
fi

# FDP
AC_ARG_ENABLE(fdp, AC_HELP_STRING([--enable-fdp],
		   [Enable Foundry Discovery Protocol]),
	      [enable_fdp=$enableval],[enable_fdp=yes])
AC_MSG_CHECKING(whether to enable FDP)
if test x$enable_fdp = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_FDP],, [Enable Foundry Discovery Protocol])
else
	AC_MSG_RESULT(no)
fi

# EDP
AC_ARG_ENABLE(edp, AC_HELP_STRING([--enable-edp],
		   [Enable Extreme Discovery Protocol]),
 	      [enable_edp=$enableval],[enable_edp=yes])
AC_MSG_CHECKING(whether to enable EDP)
if test x$enable_edp = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_EDP],, [Enable Extreme Discovery Protocol])
else
	AC_MSG_RESULT(no)
fi

# SONMP
AC_ARG_ENABLE(sonmp, AC_HELP_STRING([--enable-sonmp],
		   [Enable SynOptics Network Management Protocol]),
	      [enable_sonmp=$enableval],[enable_sonmp=yes])
AC_MSG_CHECKING(whether to enable SONMP)
if test x$enable_sonmp = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_SONMP],, [Enable SynOptics Network Management Protocol])
else
	AC_MSG_RESULT(no)
fi

#LLDPMED
AC_ARG_ENABLE(lldpmed, AC_HELP_STRING([--enable-lldpmed],
		   [Enable LLDP-MED extension]),
	      [enable_lldpmed=$enableval],[enable_lldpmed=yes])
AC_MSG_CHECKING(whether to enable LLDP-MED)
if test x$enable_lldpmed = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_LLDPMED],, [Enable LLDP-MED extension])
else
	AC_MSG_RESULT(no)
fi

#Dot1
AC_ARG_ENABLE(dot1, AC_HELP_STRING([--enable-dot1],
		   [Enable LLDP Dot1 extension]),
	      [enable_dot1=$enableval],[enable_dot1=yes])
AC_MSG_CHECKING(whether to enable Dot1)
if test x$enable_dot1 = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_DOT1],, [Enable LLDP Dot1 extension])
else
	AC_MSG_RESULT(no)
fi

#Dot3
AC_ARG_ENABLE(dot3, AC_HELP_STRING([--enable-dot3],
		   [Enable LLDP Dot3 extension]),
	      [enable_dot3=$enableval],[enable_dot3=yes])
AC_MSG_CHECKING(whether to enable Dot3)
if test x$enable_dot3 = xyes; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([ENABLE_DOT3],, [Enable LLDP Dot3 extension])
else
	AC_MSG_RESULT(no)
fi

AC_OUTPUT
