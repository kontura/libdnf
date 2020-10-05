/*
Copyright (C) 2020 Red Hat, Inc.

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

#ifndef LIBDNF_ADVISORY_ADVISORY_PACKAGE_PRIVATE_HPP
#define LIBDNF_ADVISORY_ADVISORY_PACKAGE_PRIVATE_HPP

#include "libdnf/logger/logger.hpp"
#include "libdnf/utils/utils.hpp"
#include "libdnf/base/base.hpp"

#include <solv/chksum.h>
#include <solv/repo.h>
#include <solv/util.h>

#include "libdnf/advisory/advisory_package.hpp"

#include "libdnf/rpm/solv_sack_impl.hpp"

namespace libdnf {

class AdvisoryPackage::AdvisoryPackagePrivate {
public:
    std::string get_name() const;
    std::string get_version() const;
    std::string get_evr() const;
    std::string get_arch() const;
    int get_advisory() const;

    static bool compare(const AdvisoryPackagePrivate & first, const AdvisoryPackagePrivate & second);
    static bool comparePackageNameArch(const AdvisoryPackagePrivate & adv_pkg, const rpm::Package & pkg);

private:
    friend class AdvisoryCollection;
    friend AdvisoryPackage;

    explicit AdvisoryPackagePrivate(Base & base, Id advisory, Id name, Id evr, Id arch, const char * filename);
    explicit AdvisoryPackagePrivate() = default;

    Base * base;
    Id advisory;

    Id name;
    Id evr;
    Id arch;
    const char * filename;
};

}  // namespace libdnf


#endif  // LIBDNF_ADVISORY_ADVISORY_PACKAGE_PRIVATE_HPP
