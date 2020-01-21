// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// @file pkt_receive_co.cc Defines the pkt4_receive and pkt6_receive callout functions.

#include <config.h>
#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcp/dhcp6.h>
#include <dhcp/pkt6.h>
#include <user_chk.h>
#include <user_chk_log.h>

using namespace isc::dhcp;
using namespace isc::hooks;
using namespace user_chk;
using namespace std;

// Functions accessed by the hooks framework use C linkage to avoid the name
// mangling that accompanies use of the C++ compiler as well as to avoid
// issues related to namespaces.
extern "C" {

/// @brief  This callout is called at the "pkt4_receive" hook.
///
/// This function determines if the DHCP client identified by the inbound
/// DHCP query packet is in the user registry.
/// Upon entry, the registry is refreshed. Next the hardware address is
/// extracted from query and saved to the context as the "query_user_id".
/// This id is then used to search the user registry.  The resultant UserPtr
/// whether the user is found or not, is saved to the callout context as
/// "registered_user".   This makes the registered user, if not null, available
/// to subsequent callouts.
///
/// @param handle CalloutHandle which provides access to context.
///
/// @return 0 upon success, non-zero otherwise.
int pkt4_receive(CalloutHandle& handle) {
    if (!user_registry) {
        LOG_ERROR(user_chk_logger, USER_CHK_INVALID_HOOK_STATE).arg("UserRegistry is null");
        return (1);
    }

    try {

        // Get the HWAddress to use as the user identifier.
        Pkt4Ptr query;
        handle.getArgument("query4", query);
        HWAddrPtr hwaddr = query->getHWAddr();

        // Look for the user in the registry.
        UserPtr registered_user = user_registry->findUser(*hwaddr);

        // Always assign a default class to a query based on registration
        std::string default_class = user_registry->getDefaultClassByResultType(registered_user ? ResultType::REGISTERED : ResultType::NOT_REGISTERED);
        query->addClass(default_class);

        LOG_DEBUG(user_chk_logger, isc::log::DBGLVL_COMMAND, USER_CHK_RESOLUTION)
          .arg(hwaddr->toText())
          .arg(registered_user ? "registered" : " not registered");
    } catch (const std::exception& ex) {
        LOG_ERROR(user_chk_logger, USER_CHK_PKT_RECEIVE_ERROR).arg(ex.what());
        // we handle hook errors gracefully, so that failure affects only subnets that
        // actualy make use of information provided by this hook
        // (ie. subnets that are available only to clients of a specific class)
        // hence return (0)
        return (0);
    }

    return (0);
}

/// @brief  This callout is called at the "pkt6_receive" hook.
///
/// This function determines if the DHCP client identified by the inbound
/// DHCP query packet is in the user registry.
/// Upon entry, the registry is refreshed. Next the DUID is extracted from
/// query and saved to the context as the "query_user_id". This id is then
/// used to search the user registry.  The resultant UserPtr whether the user
/// is found or not, is saved to the callout context as "registered_user".
/// This makes the registered user, if not null, available to subsequent
/// callouts.
///
/// @param handle CalloutHandle which provides access to context.
///
/// @return 0 upon success, non-zero otherwise.
int pkt6_receive(CalloutHandle& handle) {
    if (!user_registry) {
        LOG_ERROR(user_chk_logger, USER_CHK_INVALID_HOOK_STATE).arg("UserRegistry is null");
        return (1);
    }

    try {
        // Fetch the inbound packet.
        Pkt6Ptr query;
        handle.getArgument("query6", query);

        // Get the DUID to use as the user identifier.
        OptionPtr opt_duid = query->getOption(D6O_CLIENTID);
        if (!opt_duid) {
            LOG_ERROR(user_chk_logger, USER_CHK_MISSING_DUID_QUERY);
            return (1);
        }
        DuidPtr duid = DuidPtr(new DUID(opt_duid->getData()));

        // Look for the user in the registry.
        UserPtr registered_user = user_registry->findUser(*duid);

        // Always assign a default class to a query based on registration
        std::string default_class = user_registry->getDefaultClassByResultType(registered_user ? ResultType::REGISTERED : ResultType::NOT_REGISTERED);
        query->addClass(default_class);

        LOG_DEBUG(user_chk_logger, isc::log::DBGLVL_COMMAND, USER_CHK_RESOLUTION)
          .arg(duid->toText())
          .arg(registered_user ? "registered" : " not registered");
    } catch (const std::exception& ex) {
        LOG_ERROR(user_chk_logger, USER_CHK_PKT_RECEIVE_ERROR).arg(ex.what());
        // we handle hook errors gracefully, so that failure affects only subnets that
        // actualy make use of information provided by this hook
        // (ie. subnets that are available only to clients of a specific class)
        // hence return (0)
        return (0);
    }

    return (0);
}

} // end extern "C"
