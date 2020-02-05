// Copyright (C) 2020 Czech Technical University in Prague
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// @file load_unload.cc Defines the load and unload hooks library functions.

#include <util.h>

namespace user_chk {

  boost::shared_ptr<void> getConfigProperty(std::string key, isc::data::Element::types type, const std::map<std::string, isc::data::ConstElementPtr>& config) {
    return getConfigProperty(key, type, config, true);
  }

  boost::shared_ptr<void> getConfigProperty(std::string key, isc::data::Element::types type, const std::map<std::string, isc::data::ConstElementPtr>& config, bool required) {
    auto elem_it = config.find(key);

    if (elem_it == config.end()) {
      if (required) {
        isc_throw(isc::BadValue, "configuration error: Required parameter '"
                  << key << "' is missing ");
      }
      // property is not required so return an empty pointer and let the caller handle this situation (eg. provide default value)
      return boost::shared_ptr<void>();
    }
    isc::data::ConstElementPtr elem = (*elem_it).second;
    if (elem->getType() != type) {
      isc_throw(isc::BadValue, "expected type does not match type of the property. expected: " << type <<
                " actual: " << elem->getType());
    }
    switch (elem->getType()) {
    case isc::data::Element::types::integer :
      {
        int64_t value;
        elem->getValue(value);
        return boost::shared_ptr<void>(new int64_t {value});
      }
    case isc::data::Element::types::real :
      {
        double value;
        elem->getValue(value);
        return boost::shared_ptr<void>(new double {value});
      }
    case isc::data::Element::types::boolean :
      {
        bool value;
        elem->getValue(value);
        return boost::shared_ptr<void>(new bool {value});
      }
    case isc::data::Element::types::string :
      {
        boost::shared_ptr<const isc::data::StringElement> str_elem = boost::static_pointer_cast<const isc::data::StringElement>(elem);
        return boost::shared_ptr<void>(new std::string(str_elem->stringValue()));
      }
    default:
      isc_throw(isc::BadValue, "unsupported parameter type: "
                << elem->getType());

    }
  }

}
