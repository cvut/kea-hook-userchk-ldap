// Copyright (C) 2013-2015,2017 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef _USER_FILE_H
#define _USER_FILE_H

/// @file user_file.h Defines the class, UserFile, which implements the UserDataSource interface for text files.

#include <user_data_source.h>
#include <user.h>

#include <boost/shared_ptr.hpp>
#include <fstream>
#include <string>
#include <LDAPConnection.h>

namespace user_chk {


/// @brief Defines a smart pointer to a LdapConnection.
typedef boost::shared_ptr<LDAPConnection> LdapConnectionPtr;


/// @brief Thrown a UserLdap encounters an error.
/// Note that it derives from UserDataSourceError to comply with the interface.
class UserLdapError : public UserDataSourceError {
public:
    UserLdapError(const char* file, size_t line, const char* what) :
        UserDataSourceError(file, line, what)
    {}
};

/// @brief Provides a UserDataSource implementation for JSON text files.
/// This class allows a text file of JSON entries to be treated as a source of
/// User entries.  The format of the file is one user entry per line, where
/// each line contains a JSON string as follows:
///
/// { "type" : "<user type>", "id" : "<user_id>" (options)  }
///
/// where:
///
/// &lt;user_type&gt;  text label of the id type: "HW_ADDR" or "DUID"
/// &lt;user_id&gt;  the user's id as a string of hex digits with or without
/// colons (':') as a delimiter
/// (options) zero or more string elements as name-value pairs, separated by
/// commas: "opt1" : "val1",  "other_opt", "77" ...
///
/// Each entry must have a valid entry for "type" and a valid entry or "id".
///
/// If an entry contains duplicate option names, that option will be assigned
/// the last value found. This is typical JSON behavior.
/// Currently, only string option values (i.e. enclosed in quotes) are
/// supported.
///
/// Example file entries might look like this:
/// @code
///
/// { "type" : "HW_ADDR", "id" : "01AC00F03344", "opt1" : "true" }
/// { "type" : "DUID", "id" : "225060de0a0b", "opt1" : "false" }
///
/// @endcode
class UserLdap : public UserDataSource {
public:

    /// @brief Constructor
    ///
    /// Create a UserLdap for the given file name without opening the file.
    /// @param fname pathname to the input file.
    ///
    /// @throw UserLdapError if given file name is empty.
    explicit UserLdap(const std::map<std::string, isc::data::ConstElementPtr>& config_map);

    /// @brief Destructor.
    ////
    /// The destructor does call the close method.
    virtual ~UserLdap();

    /// @brief Opens the input file for reading.
    ///
    /// Upon successful completion, the file is opened and positioned to start
    /// reading from the beginning of the file.
    ///
    /// @throw UserLdapError if the file cannot be opened.
    virtual void open() override;

    /// @brief Fetches the next user from the file.
    ///
    /// Reads the next user entry from the file and attempts to create a
    /// new User from the text therein.  If there is no more data to be read
    /// it returns an empty UserPtr.
    ///
    /// @return A UserPtr pointing to the new User or an empty pointer on EOF.
    ///
    /// @throw UserLdapError if an error occurs while reading.
    //virtual UserPtr readNextUser();

    virtual UserPtr lookupUserById(const UserId& user_id) override;


    /// @brief Closes the underlying file.
    ///
    /// Method is exception safe.
    virtual void close() override;

    /// @brief Returns true if the file is open.
    ///
    /// @return True if the underlying file is open, false otherwise.
    virtual bool isOpen() const override;



private:

    /// @brief Pathname of the input text file.
    bool use_start_tls_;

    /// @brief Pathname of the input text file.
    std::string host_;

    /// @brief Pathname of the input text file.
    int64_t port_;

    /// @brief Pathname of the input text file.
    std::string basedn_;

    /// @brief Pathname of the input text file.
    std::string filter_;

    /// @brief Pathname of the input text file.
    std::string binddn_;

    /// @brief Pathname of the input text file.
    std::string bindpwd_;

    /// @brief Pathname of the input text file.
    int64_t max_query_time_;

    /// @brief Pathname of the input text file.
    int64_t max_query_result_size_;

    /// @brief Input file stream.
    LdapConnectionPtr conn_;

    bool conn_open_;

};

/// @brief Defines a smart pointer to a UserLdap.
typedef boost::shared_ptr<UserLdap> UserLdapPtr;


} // namespace user_chk

#endif
