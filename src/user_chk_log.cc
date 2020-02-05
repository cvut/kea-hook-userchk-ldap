// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
// Copyright (C) 2020 Czech Technical University in Prague
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Defines the logger used by the user check hooks library.
#include <config.h>

#include <user_chk_log.h>

namespace user_chk {

const char* USR_CHK_LOGGER_NAME = "user-chk-ldap-hooks";
isc::log::Logger user_chk_logger(USR_CHK_LOGGER_NAME);

} // namespace user_chk
