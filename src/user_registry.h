// Copyright (C) 2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef _USER_REGISTRY_H
#define _USER_REGISTRY_H

/// @file user_registry.h Defines the class, UserRegistry.

#include <dhcp/hwaddr.h>
#include <dhcp/duid.h>
#include <exceptions/exceptions.h>
#include <user.h>
#include <user_data_source.h>

#include <string>

namespace user_chk {

enum UserDataSourceType { file, ldap };

/// @brief TODO
enum ResultType {
    /// @brief TODO
    REGISTERED = 0,
    /// @brief TODO
    NOT_REGISTERED = 1
};


class Result;

/// @brief Defines a smart pointer to a User.
typedef boost::shared_ptr<Result> ResultPtr;

/// @brief Thrown UserRegistry encounters an error
class UserRegistryError : public isc::Exception {
public:
    UserRegistryError(const char* file, size_t line, const char* what) :
        isc::Exception(file, line, what)
    {}
};

/// @brief Defines a map of unique Users keyed by UserId.
typedef std::map<UserId,ResultPtr> UserCache;

/// @brief Embodies an update-able, searchable list of unique users
/// This class provides the means to create and maintain a searchable list
/// of unique users. List entries are pointers to instances of User, keyed
/// by their UserIds.
/// Users may be added and removed from the list individually or the list
/// may be updated by loading it from a data source, such as a file.
class UserRegistry {
public:
    /// @brief Constructor
    ///
    /// Creates a new registry.
    UserRegistry(const std::map<std::string, isc::data::ConstElementPtr>& cache_config,
                 const std::map<std::string, isc::data::ConstElementPtr>& defaults_config);

    /// @brief Destructor
    ~UserRegistry();

    /// @brief Adds a given user to the registry.
    ///
    /// @param user A pointer to the user to add
    ///
    /// @throw UserRegistryError if the user is null or if the user already
    /// exists in the registry.
    //void addUser(UserPtr& user);

    /// @brief Finds a user in the registry by user id
    ///
    /// @param id The user id for which to search
    ///
    /// @return A pointer to the user if found or an null pointer if not.
    const UserPtr findUser(const UserId& id);

    /// @brief Removes a user from the registry by user id
    ///
    /// Removes the user entry if found, if not simply return.
    ///
    /// @param id The user id of the user to remove
    void removeUser(const UserId& id);

    /// @brief Finds a user in the registry by hardware address
    ///
    /// @param hwaddr The hardware address for which to search
    ///
    /// @return A pointer to the user if found or an null pointer if not.
    const UserPtr findUser(const isc::dhcp::HWAddr& hwaddr);

    /// @brief Finds a user in the registry by DUID
    ///
    /// @param duid The DUID for which to search
    ///
    /// @return A pointer to the user if found or an null pointer if not.
    const UserPtr findUser(const isc::dhcp::DUID& duid);

    /// @brief Removes all entries from the registry.
    //void clearall();

    /// @brief Returns a reference to the data source.
    const UserDataSourcePtr& getSource();

    /// @brief Sets the data source to the given value.
    ///
    /// @param source reference to the data source to use.
    ///
    /// @throw UserRegistryError if new source value is null.
    void setSource(const UserDataSourcePtr& source);

    const ResultPtr fetchFromCache(const UserId& id) const;

    const ResultPtr fetchFromSource(const UserId& id);

    void evictCache();

    void cache(const UserId& id, const ResultPtr result);

    std::string getDefaultClassByResultType(ResultType type) const;

private:
    /// @brief The registry of users.
    UserCache users_;

    /// @brief The current data source of users.
    UserDataSourcePtr source_;

    uint64_t cache_positive_result_ttl_;
    uint64_t cache_negative_result_ttl_;
    size_t cache_max_size_;

    std::string default_positive_result_class_;
    std::string default_negative_result_class_;

};



/// @brief TODO
class Result {
public:

    /// @brief Constructor
    ///
    /// Constructs a new User from a given id with an empty set of properties.
    ///
    /// @param user_id Id to assign to the user
    ///
    /// @throw isc::BadValue if user id is blank.
    Result(const UserPtr user, ResultType result, time_t invalid_after);

    /// @brief Destructor
    ~Result();

    /// @brief Returns the user's id.
    ///
    /// Note that this reference can go out of scope and should not be
    /// relied upon other than for momentary use.
    const UserPtr getUser() const;

    /// @brief TODO
    ResultType getResult() const;

    /// @brief TODO
    std::time_t getInvalidAfter() const;

    /// @brief Returns true iff invalid_after_ < current time
    bool isExpired() const;

private:

    /// @brief TODO
    const UserPtr user_;

    ResultType result_;

    /// @brief Timestamp that denotes validity of this record
    /// Records with invalid_after_ that are strictly lower than a current
    /// system time should not be taken into consideration by a hook logic
    /// and should be refreshed from user data store (and possibly removed
    /// from the user data cache)
    std::time_t invalid_after_;

};


/// @brief Define a smart pointer to a UserRegistry.
typedef boost::shared_ptr<UserRegistry> UserRegistryPtr;

} // namespace user_chk

#endif
