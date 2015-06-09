AC_INIT([libwebsite], [1.0.0])
AC_CONFIG_SRCDIR([src/core.c])
AM_INIT_AUTOMAKE([1.14 subdir-objects])
orig_CFLAGS="$CFLAGS"


AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

AC_PROG_CC

dnl Supply default CFLAGS, if not specified
if test -z "$orig_CFLAGS"; then
  if test x$GCC = xyes; then
    CFLAGS="-g -O3"
  fi
fi

AC_PROG_INSTALL
AC_PROG_LIBTOOL
#AM_EXTRA_RECURSIVE_TARGETS([foo])


AC_CONFIG_FILES([Makefile ])
AC_OUTPUT
