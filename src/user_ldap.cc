// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <config.h>
#include <cc/data.h>
#include <user.h>
#include <user_chk_log.h>
#include <user_ldap.h>
#include <util.h>

#include <boost/foreach.hpp>
#include <errno.h>
#include <iostream>
#include <log/message_types.h>
#include <util/strutil.h>

namespace user_chk {

  UserLdap::UserLdap(const std::map<std::string, isc::data::ConstElementPtr>& config): conn_open_(false) {

    host_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("host", isc::data::Element::types::string, config)));
    port_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("port", isc::data::Element::types::integer, config)));
    use_start_tls_ = (* boost::static_pointer_cast<bool>(getConfigProperty("useStartTls", isc::data::Element::types::boolean, config)));
    basedn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("baseDN", isc::data::Element::types::string, config)));
    filter_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("filter", isc::data::Element::types::string, config)));
    binddn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindDN", isc::data::Element::types::string, config)));
    bindpwd_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindPwd", isc::data::Element::types::string, config)));

    conn_ = LdapConnectionPtr(new LDAPConnection(host_, port_));
    if (host_.empty()) {
        isc_throw(UserLdapError, "file name cannot be blank");
    }
    if (basedn_.empty()) {
        isc_throw(UserLdapError, "base DN cannot be blank");
    }
    if (filter_.empty()) {
        isc_throw(UserLdapError, "query cannot be blank");
    }
}

UserLdap::~UserLdap() {
  close();
};

void
UserLdap::open() {
    if (isOpen()) {
      return;
    }
    try {
      if (use_start_tls_) {
        conn_->start_tls();
        TlsOptions tls = conn_->getTlsOptions();
      }

      conn_->bind(binddn_, bindpwd_);
      conn_open_ = true;
    } catch (LDAPException &ex) {
      isc_throw(UserLdapError, "cannot open connection " << ex.what());

      std::cout << "DHCP UserCheckHook : cannot open connection: "
                << ex.what() << std::endl;

    }
}

// UserPtr
// UserLdap::readNextUser(<LdapEntry>cursorPtr) {
//     if (!isOpen()) {
//         isc_throw (UserLdapError, "cannot read, file is not open");
//     }

//     cursorPtr->nextUser();

//     if (file_.good()) {
//         char buf[USER_ENTRY_MAX_LEN];

//         // Get the next line.
//         file_.getline(buf, sizeof(buf));

//         // We got something, try to make a user out of it.
//         if (file_.gcount() > 0) {
//             return(makeUser(buf));
//         }
//     }

//     // Returns an empty user on EOF.
//     return (UserPtr());
// }

UserPtr UserLdap::lookupUserById(const UserId& userid) {

  // should be sanitized by now
  const std::string userid_str = userid.toText(':');


  std::vector<std::string> filter_args { userid_str };
  std::string f = isc::util::str::format(filter_, filter_args);

  try {
    LDAPSearchResults* entries = conn_->search(basedn_,
                                              LDAPConnection::SEARCH_SUB,
                                              f);
    if (entries == 0) {
      return UserPtr();
    }
    LDAPEntry* entry = entries->getNext();
    if (entry == 0) {
      return UserPtr();
    }
    LDAPEntry* next_entry = entries->getNext();
    if (next_entry != 0) {
      LOG_WARN(user_chk_logger, USER_CHK_MULTIPLE_RESULT_ENTRIES_RECEIVED);
      delete next_entry;
    }
    delete entry;

    UserPtr user;
    try {
        // we do not assume that the userid is stored as an LDAP attribute and
        // that it contains necessary metadata (e.g. DUID type), so we just return
        // copy of the original UserId that was part of the request
        user.reset(new User(userid));
    } catch (const std::exception& ex) {
        // should not happen
      isc_throw(UserLdapError, "UserLdap: cannot create user entry: " << ex.what());
    }
    return user;
  } catch (LDAPException& ex){
    isc_throw(UserLdapError, "UserLdap: caught ldap exception: " << ex.what());
  }
}

bool
UserLdap::isOpen() const {
    return conn_open_;
}

void
UserLdap::close() {
  if (!isOpen()) return;
  try {
    conn_->unbind();
    conn_open_ = false;
  } catch (LDAPException &ex) {
    std::cout << "UserLdap unexpected error while closing connection: "
              << ex.what() << std::endl;
  }
}

} // namespace user_chk