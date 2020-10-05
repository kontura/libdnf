/*
Copyright (C) 2018-2020 Red Hat, Inc.

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

#include <memory>
#include <vector>

namespace libdnf {

class Base;
class SolvSack;
class AdvisoryCollection;
class AdvisoryReference;

struct AdvisoryId {
public:
    AdvisoryId() = default;
    explicit AdvisoryId(int id);

    bool operator==(const AdvisoryId & other) const noexcept { return id == other.id; };
    bool operator!=(const AdvisoryId & other) const noexcept { return id != other.id; };

    int id{0};
};

inline AdvisoryId::AdvisoryId(int id) : id(id) {}

enum class AdvisoryType : int {
    UNKNOWN = 0,
    SECURITY = 1,
    BUGFIX = 2,
    ENHANCEMENT = 3,
    NEWPACKAGE = 4
};

/// An advisory
/// Represents an advisory used to track security updates
class Advisory {
public:
    using Type = AdvisoryType;

    const char *get_name() const;
    const char *get_severity() const;
    Type get_type() const;
    AdvisoryId get_id() const;
    std::vector<AdvisoryReference> get_references(const char * type = NULL) const;
    std::vector<AdvisoryCollection> get_collections() const;

    bool is_applicable() const;


    //Advisory & operator=(Advisory && advisory) = delete;

    ~Advisory();

private:
    friend class AdvisorySack;
    /// Construct the Advisory object
    /// @param id     advisory ID into libsolv pool
    /// @param base   reference to Base instance
    Advisory(AdvisoryId id, Base & base);

    AdvisoryId id;
    //TODO(amatej): have just solvsack instead?
    Base & base;
};


}  // namespace libdnf

#endif
