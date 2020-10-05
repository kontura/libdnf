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

#ifndef LIBDNF_ADVISORY_ADVISORY_PACKAGE_HPP
#define LIBDNF_ADVISORY_ADVISORY_PACKAGE_HPP

#include <memory>
#include <vector>

namespace libdnf {

class Base;
class SolvSack;

struct AdvisoryPackage {
public:
    std::string get_name() const;
    std::string get_version() const;
    std::string get_evr() const;
    std::string get_arch() const;
    int get_advisory() const;

    AdvisoryPackage(const AdvisoryPackage & src);
    AdvisoryPackage(AdvisoryPackage && src);

    AdvisoryPackage & operator=(const AdvisoryPackage & src);
    AdvisoryPackage & operator=(AdvisoryPackage && src) noexcept;
    ~AdvisoryPackage();

    static bool compare(const AdvisoryPackage & first, const AdvisoryPackage & second);
    static bool comparePackageNameArch(const AdvisoryPackage & adv_pkg, const rpm::Package & pkg);
private:
    friend class AdvisoryCollection;

    class AdvisoryPackagePrivate;

    AdvisoryPackage(AdvisoryPackagePrivate * private_pkg);

    std::unique_ptr<AdvisoryPackagePrivate> private_pkg;
};

}  // namespace libdnf

#endif
