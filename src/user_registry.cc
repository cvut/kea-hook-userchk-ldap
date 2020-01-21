// Copyright (C) 2013-2015,2017 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <config.h>
#include <cc/data.h>
#include <user_registry.h>
#include <user.h>
#include <user_chk_log.h>
#include <util.h>

namespace user_chk {

  UserRegistry::UserRegistry(const std::map<std::string, isc::data::ConstElementPtr>& defaults_config,
                             const std::map<std::string, isc::data::ConstElementPtr>& cache_config) {

  cache_positive_result_ttl_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("positiveResultTtl",
                                                                                        isc::data::Element::types::integer,
                                                                                        cache_config)));
  cache_negative_result_ttl_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("negativeResultTtl",
                                                                                        isc::data::Element::types::integer,
                                                                                        cache_config)));
  cache_max_size_ = (* boost::static_pointer_cast<int64_t>(getConfigProperty("maxSize",
                                                                             isc::data::Element::types::integer,
                                                                             cache_config)));

  default_positive_result_class_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("positiveResultClass",
                                                                                        isc::data::Element::types::string,
                                                                                        defaults_config)));
  default_negative_result_class_ = (* boost::static_pointer_cast<std::string>(getConfigProperty("negativeResultClass",
                                                                                        isc::data::Element::types::string,
                                                                                        defaults_config)));

}

UserRegistry::~UserRegistry() {
}

const ResultPtr
UserRegistry::fetchFromCache(const UserId& id) const {
  static ResultPtr miss;
  UserCache::const_iterator it = users_.find(id);
  return it == users_.end() || it->second->isExpired() ? miss : it->second;
}

const ResultPtr
UserRegistry::fetchFromSource(const UserId& id) {
    // If the source isn't open, open it.
    if (!source_->isOpen()) {
        source_->open();
    }
    static UserPtr empty;

    try {
        UserPtr user =  source_->lookupUserById(id);
        return user ?
          ResultPtr(new Result(user, ResultType::REGISTERED, std::time(nullptr) + cache_positive_result_ttl_)) :
          ResultPtr(new Result(empty, ResultType::NOT_REGISTERED, std::time(nullptr) + cache_negative_result_ttl_));
    } catch (const std::exception& ex) {
        isc_throw (UserRegistryError, "UserRegistry: refresh failed during read"
                   << ex.what());
    }
}

void
UserRegistry::evictCache() {
    auto it = users_.cbegin();
    while (it != users_.cend()) {
      if (it->second->isExpired()) {
        it = users_.erase(it);
      } else {
        ++it;
      }
    }
}

void
UserRegistry::cache(const UserId& id, const ResultPtr result) {
  auto it = users_.find(id);
  if (it != users_.end()) {
    //LOG_DEBUG(user_chk_logger, USER_CHK_MULTIPLE_RESULT_ENTRIES_RECEIVED);
    users_.erase(it);
  }

  if (users_.size() >= cache_max_size_) {
    evictCache();
  }
  // only cache new item if previous step emptied any space
  // TODO: consider forced eviction of 10% oldest values instead
  if (users_.size() < cache_max_size_) {
    users_[id] = result;
  }
}


const UserPtr
UserRegistry::findUser(const UserId& id) {
    static UserPtr unregistered;
    ResultPtr result;
    if (auto tmp = fetchFromCache(id)) {
      result = tmp;
    } else {
      result = fetchFromSource(id);
      cache(id, result);
    }
    return result->getResult() == ResultType::REGISTERED ? result->getUser() : unregistered;
}

void
UserRegistry::removeUser(const UserId& id) {
    UserCache::iterator it = users_.find(id);
    if (it != users_.end()) {
        users_.erase(it);
    }
}

const UserPtr
UserRegistry::findUser(const isc::dhcp::HWAddr& hwaddr) {
    UserId id(UserId::HW_ADDRESS, hwaddr.hwaddr_);
    return (findUser(id));
}

const UserPtr
UserRegistry::findUser(const isc::dhcp::DUID& duid) {
    UserId id(UserId::DUID, duid.getDuid());
    return (findUser(id));
}

void UserRegistry::setSource(UserDataSourcePtr& source) {
    if (!source) {
        isc_throw (UserRegistryError,
                   "UserRegistry: data source cannot be set to null");
    }

    source_ = source;
}

const UserDataSourcePtr& UserRegistry::getSource() {
    return (source_);
}

std::string UserRegistry::getDefaultClassByResultType(ResultType type) const {
  switch (type) {
  case REGISTERED:
    return (default_positive_result_class_);
  case NOT_REGISTERED:
    return (default_negative_result_class_);
  }
  isc_throw (UserRegistryError,
             "UserRegistry: Invalid result type provided when requesting default class.");
}


//********************************* Result ******************************

Result::Result(const UserPtr user, ResultType result, time_t invalid_after): user_(user), result_(result), invalid_after_(invalid_after) { }

Result::~Result() {
}

const UserPtr
Result::getUser() const {
    return (user_);
}

ResultType
Result::getResult() const {
    return (result_);
}

std::time_t
Result::getInvalidAfter() const {
    return (invalid_after_);
}

bool
Result::isExpired() const {
    return (invalid_after_ < std::time(nullptr));
}

} // namespace user_chk
