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
#include <sys/time.h>
#include <boost/foreach.hpp>
#include <errno.h>
#include <iostream>
#include <log/message_types.h>
#include <util/strutil.h>

namespace user_chk {

static void suppress_signal(int signal, struct sigaction& act, struct sigaction& oldact) {
  act.sa_handler = SIG_IGN;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaction(signal, &act, &oldact);
}

static void restore_signal(int signal, struct sigaction& oldact) {
  sigaction(signal, &oldact, NULL);
}


static void set_option(LDAP* conn, int option, const void * invalue, std::string opt_name) {
  int ret;
  if ((ret = ldap_set_option(conn, option, invalue)) != LDAP_SUCCESS) {
    LOG_ERROR(user_chk_logger, USER_CHK_USER_SOURCE_ERROR).arg("Cannot set LDAP option " + opt_name);
    isc_throw(UserLdapError, "Cannot set LDAP option " << opt_name);
  }
}

static void set_tls_options(LDAP* conn,  UserLdap::TlsMode tls_mode, isc::data::ConstElementPtr tls_opts) {
  if (!tls_opts) {}
  if (tls_mode == UserLdap::TlsMode::NONE || !tls_opts) {
    return;
  }

  const std::map<std::string, isc::data::ConstElementPtr>& config = tls_opts->mapValue();

  // TODO

}

UserLdap::UserLdap(const std::map<std::string, isc::data::ConstElementPtr>& config) {

  uri_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("uri", isc::data::Element::types::string, config)));

  basedn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("baseDN", isc::data::Element::types::string, config)));
  filter_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("filter", isc::data::Element::types::string, config)));
  binddn_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindDN", isc::data::Element::types::string, config)));
  bindpwd_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("bindPwd", isc::data::Element::types::string, config)));
  max_query_time_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("maxQueryTime", isc::data::Element::types::integer, config)));
  max_query_result_size_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("maxQueryResultSize", isc::data::Element::types::integer, config)));

  boost::shared_ptr<int64_t> max_ldap_op_tries_ptr = boost::static_pointer_cast<int64_t>(getConfigProperty("maxLdapOpTries", isc::data::Element::types::integer, config, false));
  max_ldap_op_tries_ = max_ldap_op_tries_ptr ? *max_ldap_op_tries_ptr : 10;

  if (uri_.empty()) {
    isc_throw(isc::BadValue, "LDAP URI parameter cannot be blank");
  }
  if (basedn_.empty()) {
    isc_throw(isc::BadValue, "base DN cannot be blank");
  }
  if (filter_.empty()) {
    isc_throw(isc::BadValue, "query cannot be blank");
  }

  auto elem_it = config.find("tlsMode");
  if (elem_it != config.end()) {
    isc::data::ConstElementPtr elem = (*elem_it).second;
    if (elem->getType() != isc::data::Element::types::string) {
      isc_throw(isc::BadValue, "expected type does not match type of the property. expected: string actual: " << elem->getType());
    }
    std::string tlsModeStr = elem->stringValue();
    if (tlsModeStr.empty() || tlsModeStr == "none") {
      tlsMode_ = NONE;
    } else if (tlsModeStr == "starttls") {
      tlsMode_ = STARTTLS;
    } else if (tlsModeStr == "tls") {
      tlsMode_ = TLS;
    } else {
      isc_throw(isc::BadValue, "invalid value of tlsMode property. Expected one of: [none, starttls, tls]");
    }
  }

  auto tlsopts_it = config.find("tlsOpts");
  if (tlsopts_it != config.end()) {
       isc::data::ConstElementPtr tlsopts_elem = (*tlsopts_it).second;
       if (tlsopts_elem->getType() != isc::data::Element::types::map) {
         isc_throw(isc::BadValue, "expected type does not match type of the property. expected: map actual: " << tlsopts_elem->getType());
       }
       tlsOpts_ = tlsopts_elem;
  }
}

UserLdap::~UserLdap() {
  close();
}

void UserLdap::bind() {
  struct berval creds;
  creds.bv_val = strndup(bindpwd_.c_str(), bindpwd_.length());
  if (creds.bv_val == NULL) {
    isc_throw(UserLdapError, "Unable to allocate memory to duplicate ldap_password");
  }
  creds.bv_len = bindpwd_.length();
  int ret;
  int tries = max_ldap_op_tries_;
  do {
    ret = ldap_sasl_bind_s(conn_, binddn_.c_str(), LDAP_SASL_SIMPLE,
                           &creds, NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
      LOG_DEBUG(user_chk_logger, isc::log::DBGLVL_COMMAND, USER_CHK_LDAP_SERVER_DOWN_RECONNECT_ERROR)
        .arg("bind")
        .arg(ret)
        .arg(tries - 1);
      //sleep(1);
    }
  } while (ret != LDAP_SUCCESS && (--tries) > 0);

  free(creds.bv_val);

  if (ret != LDAP_SUCCESS) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_OPEN_ERROR).arg(ldap_err2string(ret));
    isc_throw(UserLdapError, "Cannot bind to LDAP server. err=" << ret << " " << ldap_err2string(ret));
    close();
  }
}

void UserLdap::initTlsSession() {
  try {

    switch (tlsMode_) {
    case TLS:
      {
        int opt = LDAP_OPT_X_TLS_HARD;
        set_option(conn_, LDAP_OPT_X_TLS, &opt, "LDAP_OPT_X_TLS");
      }
      break;
      case STARTTLS:
      {
        int ret;
        int tries = max_ldap_op_tries_;
        do {
          ret = ldap_start_tls_s(conn_, NULL, NULL);
          if (ret != LDAP_SUCCESS) {
            LOG_DEBUG(user_chk_logger, isc::log::DBGLVL_COMMAND, USER_CHK_LDAP_SERVER_DOWN_RECONNECT_ERROR)
              .arg("starttls")
              .arg(ret)
              .arg(tries - 1);
            //sleep(1);
          }
        } while (ret != LDAP_SUCCESS && (--tries) > 0);

        if (ret != LDAP_SUCCESS) {
          LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_OPEN_ERROR).arg(ldap_err2string(ret));
          isc_throw(UserLdapError, "Cannot start TLS session. err=" << ret << " " << ldap_err2string(ret));
        }
      }
      break;
    }
  } catch (const UserLdapError& ex) {
    close();
    throw;
  }
}

void
UserLdap::open() {
  if (conn_ != NULL) {
    LOG_WARN(user_chk_logger, USER_CHK_INVALID_LDAP_DATA_STORE_STATE).arg("Connection is already open.");
    return;
  }

  int ret;
  ret = ldap_initialize(&conn_, uri_.c_str());

  if (conn_ == NULL || ret != LDAP_SUCCESS) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_OPEN_ERROR).arg(ldap_err2string(ret));
    isc_throw(UserLdapError, "Cannot initialize LDAP connection. err=" << ret << " " << ldap_err2string(ret));
  }

  int version = LDAP_VERSION3;
  if ((ret = ldap_set_option(conn_, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_OPT_SUCCESS) {
    LOG_ERROR(user_chk_logger, USER_CHK_USER_SOURCE_ERROR).arg("Cannot set LDAP protocol version.");
  }

   struct timeval timeout = {};
   timeout.tv_sec = max_query_time_;
   timeout.tv_usec = 0;
   set_option(conn_, LDAP_OPT_TIMEOUT, &timeout, "LDAP_OPT_TIMEOUT");
   set_option(conn_, LDAP_OPT_NETWORK_TIMEOUT, &timeout, "LDAP_OPT_NETWORK_TIMEOUT");

   set_tls_options(conn_, tlsMode_, tlsOpts_);

   initTlsSession();

   bind();
}

UserPtr UserLdap::lookupUserById(const UserId& userid) {
    const std::string userid_str = userid.toText(':');
    std::vector<std::string> filter_args { userid_str };
    std::string f = isc::util::str::format(filter_, filter_args);
    int ret;
    LDAPMessage * res;
    struct timeval timeout = {};
    timeout.tv_sec = max_query_time_;
    timeout.tv_usec = 0;

    // If the connection isn't open, open it.
    if (!isOpen()) {
        open();
    }

    // when connection is closed from server side, fd is closed and on the next attempt
    // SIGPIPE signal is received, which terminates the process
    // setting SIG_IGN as a sig. handler causes EPIPE error to be returned instead
    // for better explanation see: https://pmhahn.github.io/SIGPIPE/
    {
      struct sigaction oldact = {}, act = {};
      suppress_signal(SIGPIPE, act, oldact);
      ret = ldap_search_ext_s(conn_, basedn_.c_str(), LDAP_SCOPE_SUBTREE, f.c_str(), NULL, 0,
                              NULL, NULL, &timeout, max_query_result_size_, &res);
      restore_signal(SIGPIPE, oldact);
    }

    if(ret == LDAP_SERVER_DOWN) {
      LOG_DEBUG(user_chk_logger, isc::log::DBGLVL_COMMAND, USER_CHK_LDAP_SERVER_DOWN_RECONNECT_ERROR)
        .arg("search")
        .arg(ret)
        .arg(1);

      {
        struct sigaction oldact = {}, act = {};
        suppress_signal(SIGPIPE, act, oldact);
        ret = ldap_search_ext_s(conn_, basedn_.c_str(), LDAP_SCOPE_SUBTREE, f.c_str(), NULL, 0,
                                NULL, NULL, &timeout, max_query_result_size_, &res);
        restore_signal(SIGPIPE, oldact);
      }
    }

    if (ret != LDAP_SUCCESS)  {
      if (res) {
        ldap_msgfree(res);
        res = NULL;
      }
      LOG_ERROR(user_chk_logger, USER_CHK_LDAP_ERROR).arg(ldap_err2string (ret));
      close();
      isc_throw(UserLdapError, "UserLdap: unexpected error while performing LDAP operation" << ldap_err2string (ret));
    }

    int entry_count = ldap_count_entries(conn_, res);

    if (entry_count == -1) {
      isc_throw(UserLdapError, "UserLdap: failed to retrieve entry count from the result set");
    } else if (entry_count == 0) {
      return UserPtr();
    } else if (entry_count != 1) {
      LOG_WARN(user_chk_logger, USER_CHK_MULTIPLE_RESULT_ENTRIES_RECEIVED).arg(entry_count);
    }

    if (res) ldap_msgfree(res);

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
    return (user);
  //  } catch (LDAPException& ex) {
  //    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_ERROR).arg(ex.what());
    // we assume the exception was caused by misconfiguration (on hook side
    // or LDAP server side) or by a network error. In any case, we probably want to
    // handle the issue in new connection  so we close the connection here
    // so it can be reopened on the next request
  // close();
  //isc_throw(UserLdapError, "UserLdap: caught ldap exception: ");
  //}
}

bool
UserLdap::isOpen() const {
  return (conn_ != NULL);
}

void
UserLdap::close() {
  if (!isOpen()) return;

  int ret;
  /*
   ** ldap_unbind after a LDAP_SERVER_DOWN result
   ** causes a SIGPIPE and the process gets terminated,
   ** if it doesn't handle it...
   */
  {
    struct sigaction oldact = {}, act = {};
    suppress_signal(SIGPIPE, act, oldact);
    ret = ldap_unbind_ext_s(conn_, NULL, NULL);
    restore_signal(SIGPIPE, oldact);
  }
  conn_ = NULL;
  if (ret) {
    LOG_ERROR(user_chk_logger, USER_CHK_LDAP_CONN_CLOSE_ERROR).arg(ldap_err2string(ret));
  }
}

} // namespace user_chk
