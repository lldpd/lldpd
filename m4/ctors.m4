#
# lldp_CHECK_CTORS
#
AC_DEFUN([lldp_CHECK_CTORS], [

  # Compiler support
  AX_GCC_FUNC_ATTRIBUTE(constructor)
  if test x"$ac_cv_have_func_attribute_constructor" = x"no"; then
    AC_MSG_FAILURE([*** GCC constructor function attribute mandatory])
  fi
  AX_GCC_FUNC_ATTRIBUTE(constructor_priority)
  AX_GCC_FUNC_ATTRIBUTE(destructor)
  if test x"$ac_cv_have_func_attribute_destructor" = x"no"; then
    AC_MSG_FAILURE([*** GCC destructor function attribute mandatory])
  fi

  # Runtime support (libc)
  AC_CACHE_CHECK([constructor/destructor runtime support], lldp_cv_ctor_runtime, [
    dnl We need to observe some sideeffect. When
    dnl constructor/destructors are running, we may not have a working
    dnl standard output.
    true > conftest.1
    true > conftest.2
    AC_RUN_IFELSE([AC_LANG_PROGRAM([
      @%:@include <unistd.h>
      void ctor1(void) __attribute__((constructor));
      void ctor1() { unlink("conftest.1"); }
      void ctor2(void) __attribute__((destructor));
      void ctor2() { unlink("conftest.2"); }], [])
    ], [
      if test -r conftest.1 -o -r conftest.2; then
        lldp_cv_ctor_runtime=no
      else
        lldp_cv_ctor_runtime=yes
      fi
    ], [
      dnl Unable to build the check
      lldp_cv_ctor_runtime=no
    ], [
      dnl Cross compilation
      lldp_cv_ctor_runtime=yes
    ])
  ])

  if test x"$lldp_cv_ctor_runtime" = x"no"; then
    AC_MSG_FAILURE([*** Constructor/destructor runtime support is missing])
  fi
])
