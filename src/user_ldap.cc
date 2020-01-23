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
#include <signal.h>

#include <boost/foreach.hpp>
#include <errno.h>
#include <iostream>
#include <log/message_types.h>
#include <util/strutil.h>

namespace user_chk {

  UserLdap::UserLdap(const std::map<std::string, isc::data::ConstElementPtr>& config): conn_(LdapConnectionPtr()) {

    host_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("host", isc::data::Element::types::string, config)));
    port_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("port", isc::data::Element::types::integer, config)));
    use_start_tls_ = (* boost::static_pointer_cast<bool>(getConfigProperty("useStartTls", isc::data::Element::types::boolean, config)));
    basedn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("baseDN", isc::data::Element::types::string, config)));
    filter_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("filter", isc::data::Element::types::string, config)));
    binddn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindDN", isc::data::Element::types::string, config)));
    bindpwd_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindPwd", isc::data::Element::types::string, config)));
    max_query_time_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("maxQueryTime", isc::data::Element::types::integer, config)));
    max_query_result_size_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("maxQueryResultSize", isc::data::Element::types::integer, config)));

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
  try {
    conn_->unbind();
  } catch (LDAPException &ex) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_CLOSE_ERROR).arg(ex.what());
  }
}

void
UserLdap::open() {
    if (conn_) {
      return;
    }
    try {
      LDAPConnection * conn = new LDAPConnection(host_, port_);
      LDAPConstraints * constrs = new LDAPConstraints();
      constrs->setMaxTime(max_query_time_);
      constrs->setSizeLimit(max_query_result_size_);
      conn->setConstraints(constrs);

      conn_.reset(conn);

      if (use_start_tls_) {
        conn_->start_tls();
        TlsOptions tls = conn_->getTlsOptions();
      }
      conn_->bind(binddn_, bindpwd_);
    } catch (LDAPException &ex) {
      LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_OPEN_ERROR).arg(ex.what());
      isc_throw(UserLdapError, "cannot open connection");
    }
}

UserPtr UserLdap::lookupUserById(const UserId& userid) {
  const std::string userid_str = userid.toText(':');

  std::vector<std::string> filter_args { userid_str };
  std::string f = isc::util::str::format(filter_, filter_args);

  try {

    // when connection is closed from server side, fd is closed and on next attempt
    // the SIGPIPE signal is received, which terminates process
    // setting SIG_IGN as a sig. handler means that EPIPE error is returned instead
    // for better explanation see: https://pmhahn.github.io/SIGPIPE/
    struct sigaction oldact = {}, act = {};
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    sigaction(SIGPIPE, &act, &oldact);
    LDAPSearchResults* entries = conn_->search(basedn_,
                                               LDAPConnection::SEARCH_SUB,
                                               f);
    sigaction(SIGPIPE, &oldact, NULL);

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
    delete entries;

    UserPtr user;
    try {
        // we do not assume that the userid is stored as an LDAP attribute and
        // that it contains necessary metadata (e.g. DUID type), so we just return
        // copy of the original UserId that was part of the original request
        user.reset(new User(userid));
    } catch (const std::exception& ex) {
        // should not happen
      LOG_ERROR(user_chk_logger, USER_CHK_LDAP_ERROR).arg(ex.what());
      isc_throw(UserLdapError, "UserLdap: cannot create user entry");
    }
    return user;
  } catch (LDAPException& ex) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_ERROR).arg(ex.what());
    // we assume the exception was caused by misconfiguration (on hook side
    // or LDAP server side) or by a network error. In any case, we probably want to
    // handle the issue in new connection  so we close the connection here
    // so it can be reopened on the next request
    close();
    isc_throw(UserLdapError, "UserLdap: caught ldap exception: ");
  }
}

bool
UserLdap::isOpen() const {
  return (conn_.get() != 0);
}

void
UserLdap::close() {
  try {
    conn_->unbind();
  } catch (LDAPException &ex) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_CLOSE_ERROR).arg(ex.what());
  }
  conn_.reset();
}

} // namespace user_chk
