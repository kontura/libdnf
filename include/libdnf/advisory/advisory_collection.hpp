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

#ifndef LIBDNF_ADVISORY_ADVISORY_COLLECTION_HPP
#define LIBDNF_ADVISORY_ADVISORY_COLLECTION_HPP


#include <vector>
#include "advisory_package.hpp"
#include "advisory_module.hpp"
#include "advisory.hpp"

namespace libdnf {

class Base;

//TODO(amatej): Do we actually need this class? (it didn't ended up needed in DNF4)
struct AdvisoryCollection {
public:
    //std::vector<AdvisoryPackage> get_packages(bool with_filenames = false) const;
    void get_packages(std::vector<AdvisoryPackage> & output, bool with_filenames = false) const;
    std::vector<AdvisoryModule> get_modules() const;

    bool is_applicable() const;

private:
    friend class Advisory;

    AdvisoryCollection(Base & base, AdvisoryId advisory, int index);

    Base & base;
    AdvisoryId advisory;

    // AdvisoryCollections don't have their own Id, there store it's index (just like advisory reference)
    int index;
};

}  // namespace libdnf

#endif
