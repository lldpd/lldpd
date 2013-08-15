#
# lldp_ARG_WITH
#

dnl lldp_ARG_WITH(name, help1, default)

AC_DEFUN([lldp_ARG_WITH],[
  AC_ARG_WITH([$1],
	AS_HELP_STRING([--with-$1],
		[$2 @<:@default=$3@:>@]),[
        AC_DEFINE_UNQUOTED(AS_TR_CPP([$1]), ["$withval"], [$2])
        AC_SUBST(AS_TR_CPP([$1]), [$withval])],[
	AC_DEFINE_UNQUOTED(AS_TR_CPP([$1]), ["$3"], [$2])
        AC_SUBST(AS_TR_CPP([$1]), [$3])
        eval with_[]m4_translit([$1], [-+.], [___]))="$3"
])])

dnl lldp_ARG_ENABLE(name, help1, default)

AC_DEFUN([lldp_ARG_ENABLE],[
  AC_ARG_ENABLE([$1],
	AS_HELP_STRING([--enable-$1],
		[Enable $2 @<:@default=$3@:>@]),
	[enable_$1=$enableval], [enable_$1=$3])
  AC_MSG_CHECKING(whether to enable $2)
  if test x"$enable_$1" = x"yes"; then
     AC_MSG_RESULT(yes)
     AC_DEFINE([ENABLE_]AS_TR_CPP([$1]),, [$2])
  else
     AC_MSG_RESULT(no)
  fi
])
