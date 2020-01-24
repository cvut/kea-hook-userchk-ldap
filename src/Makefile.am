
# AM_CPPFLAGS  = -I$(top_builddir)/src/lib -I$(top_srcdir)/src/lib
AM_CPPFLAGS  = -I/usr/include/kea
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS  = $(KEA_CXXFLAGS)

# Some versions of GCC warn about some versions of Boost regarding
# missing initializer for members in its posix_time.
# https://svn.boost.org/trac/boost/ticket/3477
# But older GCC compilers don't have the flag.
AM_CXXFLAGS += $(WARNING_NO_MISSING_FIELD_INITIALIZERS_CFLAG)
AM_CXXFLAGS += -std=c++11

# Tell automake that the message files are built as part of the build process
# (so that they are built before the main library is built).
BUILT_SOURCES = user_chk_messages.h user_chk_messages.cc

EXTRA_DIST = libdhcp_user_chk_ldap.dox
# Ensure that the message file is included in the distribution
EXTRA_DIST += user_chk_messages.mes

# Get rid of generated message files on a clean
CLEANFILES = *.gcno *.gcda user_chk_messages.h user_chk_messages.cc

# convenience archive

noinst_LTLIBRARIES = libducl.la

libducl_la_SOURCES  =
libducl_la_SOURCES += load_unload.cc
libducl_la_SOURCES += subnet_select_co.cc
libducl_la_SOURCES += user.cc user.h
libducl_la_SOURCES += user_chk.h
libducl_la_SOURCES += user_chk_log.cc user_chk_log.h
libducl_la_SOURCES += user_chk_messages.cc user_chk_messages.h
libducl_la_SOURCES += user_data_source.h
libducl_la_SOURCES += user_ldap.cc user_ldap.h
libducl_la_SOURCES += user_registry.cc user_registry.h
libducl_la_SOURCES += util.cc util.h
libducl_la_SOURCES += version.cc

libducl_la_CXXFLAGS = $(AM_CXXFLAGS)
libducl_la_CPPFLAGS = $(AM_CPPFLAGS)

# install the shared object into $(libdir)/kea/hooks
lib_hooksdir = $(libdir)/kea/hooks
lib_hooks_LTLIBRARIES = libdhcp_user_chk_ldap.la

libdhcp_user_chk_ldap_la_SOURCES  =
libdhcp_user_chk_ldap_la_LDFLAGS  = $(AM_LDFLAGS)
libdhcp_user_chk_ldap_la_LDFLAGS  += -avoid-version -export-dynamic -module
libdhcp_user_chk_ldap_la_LDFLAGS  += -lldapcpp -lkea-dhcpsrv -lkea-dhcp++ -lkea-hooks -lkea-log -lkea-util -lkea-exceptions -lkea-cc
# # -rpath /nowhere is a hack to trigger libtool to not create a
# # convenience archive, resulting in shared modules
# libdhcp_user_chk_ldap_la_LDFLAGS  += -rpath /nowhere
libdhcp_user_chk_ldap_la_LIBADD  = libducl.la
# libdhcp_user_chk_ldap_la_LIBADD  += $(top_builddir)/src/lib/hooks/libkea-hooks.la
# libdhcp_user_chk_ldap_la_LIBADD  += $(top_builddir)/src/lib/log/libkea-log.la
# libdhcp_user_chk_ldap_la_LIBADD  += $(top_builddir)/src/lib/util/libkea-util.la
# libdhcp_user_chk_ldap_la_LIBADD  += $(top_builddir)/src/lib/exceptions/libkea-exceptions.la
libdhcp_user_chk_ldap_la_LIBADD  += $(LOG4CPLUS_LIBS)
libdhcp_user_chk_ldap_la_LIBADD  += $(BOOST_LIBS)


# If we want to get rid of all generated messages files, we need to use
# make maintainer-clean. The proper way to introduce custom commands for
# that operation is to define maintainer-clean-local target. However,
# make maintainer-clean also removes Makefile, so running configure script
# is required.  To make it easy to rebuild messages without going through
# reconfigure, a new target messages-clean has been added.
maintainer-clean-local:
	rm -f user_chk_messages.h user_chk_messages.cc

# To regenerate messages files, one can do:
#
# make messages-clean
# make messages
#
# This is needed only when a .mes file is modified.
messages-clean: maintainer-clean-local

if GENERATE_MESSAGES

# Define rule to build logging source files from message file
messages: user_chk_messages.h user_chk_messages.cc
	@echo Message files regenerated

user_chk_messages.h user_chk_messages.cc: user_chk_messages.mes
	kea-msg-compiler user_chk_messages.mes

else

messages user_chk_messages.h user_chk_messages.cc:
	@echo Messages generation disabled. Configure with --enable-generate-messages to enable it.

endif
