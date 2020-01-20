// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef USER_CHK_UTIL_H
#define USER_CHK_UTIL_H

#include <config.h>
#include <boost/shared_ptr.hpp>
#include <cc/data.h>

namespace user_chk {

/// \brief A Set of C++ Utilities for Manipulating Strings

///
/// \brief A standard string util exception that is thrown if getToken or
/// numToToken are called with bad input data
///
boost::shared_ptr<void> getConfigProperty(std::string key, isc::data::Element::types type, const std::map<std::string, isc::data::ConstElementPtr>& config);

}

#endif
