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

#ifndef LIBDNF_ADVISORY_ADVISORY_REFERENCE_HPP
#define LIBDNF_ADVISORY_ADVISORY_REFERENCE_HPP

#include "advisory.hpp"

#include <memory>
#include <vector>

namespace libdnf {

class Base;
class SolvSack;

enum class AdvisoryReferenceType : int {
    UNKNOWN = 0,
    BUGZILLA = 1,
    CVE = 2,
    VENDOR = 3,
};

struct AdvisoryReference {
public:
    using Type = AdvisoryReferenceType;

    std::string get_id() const;
    Type get_type() const;
    std::string get_title() const;
    std::string get_url() const;
private:
    friend class Advisory;
    AdvisoryReference(Base & base, AdvisoryId advisory, int index);

    Base & base;
    AdvisoryId advisory;
    // We cannot store IDs of data (id, type, title, url) because they don't have ids set in libsolv (its only strings)
    int index;
};

}  // namespace libdnf

#endif
