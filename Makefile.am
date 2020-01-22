SUBDIRS = src  # FIXME: tests

ACLOCAL_AMFLAGS = -I m4

# for static C++ check using cppcheck (when available)
cppcheck:
	cppcheck -I./src --enable=all \
		--suppressions-list=src/cppcheck-suppress.lst --inline-suppr \
		--quiet --error-exitcode=1 \
		--template '{file}:{line}: check_fail: {message} ({severity},{id})' \
		src
