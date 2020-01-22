AC_INIT(kea-hook-userchk-ldap,0.0-git)
AM_INIT_AUTOMAKE([-Wall -Wno-extra-portability -Werror foreign])
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
# Use C++ language
AC_PROG_CXX

# On FreeBSD (and probably some others), clang++ does not meet an autoconf
# assumption in identifying libtool configuration regarding shared library:
# the configure script will execute "$CC -shared $CFLAGS/$CXXFLAGS -v" and
# expect the output contains -Lxxx or -Ryyy.  This is the case for g++, but
# not for clang++, and, as a result, it will cause various errors in linking
# programs or running them with a shared object (such as some of our python
# scripts).
# To work around this problem we define a temporary variable
# "CXX_LIBTOOL_LDFLAGS".  It's expected to be defined as, e.g, "-L/usr/lib"
# to temporarily fake the output so that it will be compatible with that of
# g++.
CFLAGS_SAVED=$CFLAGS
CXXFLAGS_SAVED=$CXXFLAGS
CFLAGS="$CFLAGS $CXX_LIBTOOL_LDFLAGS"
CXXFLAGS="$CXXFLAGS $CXX_LIBTOOL_LDFLAGS"
LT_INIT
CFLAGS=$CFLAGS_SAVED
CXXFLAGS=$CXXFLAGS_SAVED

# Use C++ language
AC_LANG([C++])

# Identify the compiler: this check must be after AC_PROG_CXX and AC_LANG.
AM_CONDITIONAL(USE_GXX, test "X${GXX}" = "Xyes")
AC_CHECK_DECL([__SUNPRO_CC], [SUNCXX="yes"], [SUNCXX="no"])
AC_CHECK_DECL([__clang__], [CLANGPP="yes"], [CLANGPP="no"])
AM_CONDITIONAL(USE_CLANGPP, test "X${CLANGPP}" = "Xyes")

AC_ARG_ENABLE(generate_messages, [AC_HELP_STRING([--enable-generate-messages],
  [indicates that the messages files will be regenerated. [default=no]])],
  enable_generate_messages=$enableval, enable_generate_messages=no)

AM_CONDITIONAL([GENERATE_MESSAGES], [test x$enable_generate_messages != xno])

# cross compiling is not compatible with enable-generate-messages.
if test "$cross_compiling" = "yes"; then
    if test "$enable_generate_messages" != "no"; then
        AC_MSG_WARN([To build the message compiler is not compatible with cross compiling])
    fi
fi

#AX_CXX_CHECK_LIB(ldapcpp, [LDAPSchema])
# FIXME: figure out the way to use AC_SEARCH_LIBS or similar for this if possible
dnl _found_ldapcpplib=no
dnl AC_CHECK_HEADER(LDAPConnection.h,[_found_ldapcpplib=yes])
dnl if [[ "$_found_ldapcpplib" = "no" ]]; then
dnl      AC_MSG_ERROR(Headers for ldapcpp are missing. Please install the package openldap-c++.)
dnl fi

AC_CONFIG_FILES([
 Makefile \
 src/Makefile
])
AC_OUTPUT
