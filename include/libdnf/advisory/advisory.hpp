/*
Copyright (C) 2021 Red Hat, Inc.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIBDNF_ADVISORY_ADVISORY_HPP
#define LIBDNF_ADVISORY_ADVISORY_HPP

#include <libdnf/rpm/solv_sack.hpp>

#include <vector>


namespace libdnf::advisory {

class AdvisoryCollection;
class AdvisoryReference;

typedef libdnf::rpm::PackageId AdvisoryId;

//TODO(amatej): consider defining these as individual numbers, not as bits in int.
//              This allows us faster iteration, but all public APIs should accept
//              only individual values (in a vector) not bitwise ored multiple values.
//              (here the OR and AND operators are public)
/// Type of advisory
enum class AdvisoryType : uint32_t {
    UNKNOWN = (1 << 0),
    SECURITY = (1 << 1),
    BUGFIX = (1 << 2),
    ENHANCEMENT = (1 << 3),
    NEWPACKAGE = (1 << 4)
};

inline AdvisoryType operator|(AdvisoryType lhs, AdvisoryType rhs) {
    return static_cast<AdvisoryType>(
        static_cast<std::underlying_type<AdvisoryType>::type>(lhs) |
        static_cast<std::underlying_type<AdvisoryType>::type>(rhs));
}

inline AdvisoryType operator&(AdvisoryType lhs, AdvisoryType rhs) {
    return static_cast<AdvisoryType>(
        static_cast<std::underlying_type<AdvisoryType>::type>(lhs) &
        static_cast<std::underlying_type<AdvisoryType>::type>(rhs));
}

//TODO(amatej): consider defining these as individual numbers, not as bits in int.
//              This allows us faster iteration, but all public APIs should accept
//              only individual values (in a vector) not bitwise ored multiple values.
//              (here the OR and AND operators are public)
/// Type of advisory reference
enum class AdvisoryReferenceType : uint32_t {
    UNKNOWN = (1 << 0),
    BUGZILLA = (1 << 1),
    CVE = (1 << 2),
    VENDOR = (1 << 3),
};

inline AdvisoryReferenceType operator|(AdvisoryReferenceType lhs, AdvisoryReferenceType rhs) {
    return static_cast<AdvisoryReferenceType>(
        static_cast<std::underlying_type<AdvisoryReferenceType>::type>(lhs) |
        static_cast<std::underlying_type<AdvisoryReferenceType>::type>(rhs));
}

inline AdvisoryReferenceType operator&(AdvisoryReferenceType lhs, AdvisoryReferenceType rhs) {
    return static_cast<AdvisoryReferenceType>(
        static_cast<std::underlying_type<AdvisoryReferenceType>::type>(lhs) &
        static_cast<std::underlying_type<AdvisoryReferenceType>::type>(rhs));
}

/// An advisory, represents advisory used to track security updates
class Advisory {
public:
    /// Construct the Advisory object
    ///
    /// @param sack   Reference to libdnf::rpm::SolvSack instance which holds are the data.
    /// @param id     AdvisoryId into libsolv pool.
    /// @return New Advisory instance.
    Advisory(libdnf::rpm::SolvSack & sack, AdvisoryId id);

    /// Destroy the Advisory object
    ~Advisory();

    using Type = AdvisoryType;

    /// Get name of this advisory.
    ///
    /// @return Name of this advisory as std::string.
    std::string get_name() const;

    /// Get severity of this advisory.
    ///
    /// @return Severity of this advisory as std::string.
    std::string get_severity() const;

    /// Get type of this advisory.
    ///
    /// @return Type of this advisory.
    Type get_type() const;

    /// Get type of this advisory.
    ///
    /// @return Type of this advisory as const char* !! (temporal values)
    const char * get_type_cstring() const;

    /// Get AdvisoryId.
    ///
    /// @return AdvisoryId of this advisory.
    AdvisoryId get_id() const;

    /// Get all references of specified type from this advisory.
    ///
    /// @param ref_type     What type of references to get. If not specified gets all types.
    /// @return Vector of AdvisoryReference objects.
    std::vector<AdvisoryReference> get_references(
        AdvisoryReferenceType ref_type = AdvisoryReferenceType::BUGZILLA | AdvisoryReferenceType::CVE |
                                         AdvisoryReferenceType::VENDOR) const;

    /// Get all collections from this advisory.
    ///
    /// @return Vector of AdvisoryCollection objects.
    std::vector<AdvisoryCollection> get_collections() const;

    /// Check whether at least one collection from this advisory is applicable.
    ///
    /// @return True if applicable, False otherwise.
    bool is_applicable() const;

    /// Convert AdvisoryType to c string representation
    ///
    /// @param type     AdvisoryType to convert.
    /// @return Converted AdvisoryType as c string (temporal value).
    static const char * advisory_type_to_cstring(Type type);

private:
    AdvisoryId id;
    libdnf::rpm::SolvSackWeakPtr sack;
};


}  // namespace libdnf::advisory

#endif