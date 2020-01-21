// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// @file load_unload.cc Defines the load and unload hooks library functions.

#include <config.h>

#include <hooks/hooks.h>
#include <user_chk_log.h>
#include <user_registry.h>
//#include <user_file.h>
#include <user_ldap.h>
#include <util.h>

#include <iostream>
#include <fstream>
#include <errno.h>

using namespace isc::hooks;
using namespace user_chk;

/// @brief Pointer to the registry instance.
UserRegistryPtr user_registry;

UserDataSourcePtr make_datasource(const isc::data::ConstElementPtr source_type,
                                  const std::map<std::string, isc::data::ConstElementPtr>& config_map) {
  if (!source_type) {
    isc_throw(isc::BadValue, "Parameter source_type is missing.");
  }

  //  if (source_type == "file") return new UserFile(config);
  if (source_type->stringValue() == "ldap") return UserDataSourcePtr(new UserLdap(config_map));

  isc_throw(isc::BadValue, "Invalid source_type parameter. Allowed values are one of ['file','ldap'].");
}

// Functions accessed by the hooks framework use C linkage to avoid the name
// mangling that accompanies use of the C++ compiler as well as to avoid
// issues related to namespaces.
extern "C" {

/// @brief Called by the Hooks library manager when the library is loaded.
///
/// Instantiates the UserRegistry and opens the outcome file. Failure in
/// either results in a failed return code.
///
/// @return Returns 0 upon success, non-zero upon failure.
int load(LibraryHandle& handle) {
    // non-zero indicates an error.
    int ret_val = 0;

    try {

        isc::data::ConstElementPtr cache_config = handle.getParameter("cache");
        if (!cache_config || cache_config->getType() != isc::data::Element::types::map) {
           isc_throw(isc::BadValue, "The mandatory parameter \"cache\" has an invalid type. Allowed type is map.");
        }

        isc::data::ConstElementPtr defaults_config = handle.getParameter("defaults");
        if (!defaults_config || defaults_config->getType() != isc::data::Element::types::map) {
           isc_throw(isc::BadValue, "The mandatory parameter \"defaults\" has an invalid type. Allowed type is map.");
        }

        // Instantiate the registry.
        user_registry.reset(new UserRegistry(cache_config->mapValue(), defaults_config->mapValue()));

        isc::data::ConstElementPtr src_config = handle.getParameter("source");
        if (!src_config || src_config->getType() != isc::data::Element::types::map) {
           isc_throw(isc::BadValue, "The mandatory parameter \"source\" is either missing or has invalid type. Allowed type is \"map\".");
        }

        // Create the data source.
        UserDataSourcePtr source = make_datasource(handle.getParameter("sourceType"),
                                                   src_config->mapValue());

        // Set the registry's data source
        user_registry->setSource(source);

    }
    catch (const std::exception& ex) {
        // Log the error and return failure.
        LOG_ERROR(user_chk_logger, USER_CHK_HOOK_LOAD_ERROR)
            .arg(ex.what());
        ret_val = 1;
    }

    return (ret_val);
}

/// @brief Called by the Hooks library manager when the library is unloaded.
///
/// Destroys the UserRegistry and closes the outcome file.
///
/// @return Always returns 0.
int unload() {
    try {
        user_registry.reset();
    } catch (const std::exception& ex) {
        // On the off chance something goes awry, catch it and log it.
        // @todo Not sure if we should return a non-zero result or not.
        LOG_ERROR(user_chk_logger, USER_CHK_HOOK_UNLOAD_ERROR)
            .arg(ex.what());
    }

    return (0);
}

}
