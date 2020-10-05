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

#include "libdnf/logger/logger.hpp"
#include "libdnf/utils/utils.hpp"
#include "libdnf/base/base.hpp"
#include "libdnf/rpm/nevra.hpp"

#include <solv/chksum.h>
#include <solv/repo.h>
#include <solv/util.h>

#include "advisory_package_private.hpp"

#include "libdnf/advisory/advisory_package.hpp"

#include "libdnf/rpm/solv_sack_impl.hpp"
#include "libdnf/rpm/solv/package_private.hpp"

namespace libdnf {

// AdvisoryPackage
AdvisoryPackage::AdvisoryPackage(AdvisoryPackagePrivate * private_pkg)
    : private_pkg(private_pkg)
{}

AdvisoryPackage::~AdvisoryPackage() = default;

AdvisoryPackage::AdvisoryPackage(const AdvisoryPackage & src) : private_pkg(new AdvisoryPackagePrivate) { *private_pkg = *src.private_pkg; }
AdvisoryPackage::AdvisoryPackage(AdvisoryPackage && src) : private_pkg(new AdvisoryPackagePrivate) { private_pkg.swap(src.private_pkg); }

AdvisoryPackage & AdvisoryPackage::operator=(const AdvisoryPackage & src) {
    *private_pkg = *src.private_pkg;
    return *this;
}

AdvisoryPackage &
AdvisoryPackage::operator=(AdvisoryPackage && src) noexcept
{
        private_pkg.swap(src.private_pkg);
        return *this;
}


std::string AdvisoryPackage::get_name() const {
    return private_pkg->get_name();
}

std::string AdvisoryPackage::get_version() const {
    return private_pkg->get_version();
}

std::string AdvisoryPackage::get_evr() const {
    return private_pkg->get_evr();
}
std::string AdvisoryPackage::get_arch() const {
    return private_pkg->get_arch();
}
int AdvisoryPackage::get_advisory() const {
    return private_pkg->get_advisory();
}
bool AdvisoryPackage::compare(const AdvisoryPackage & first, const AdvisoryPackage & second) {
    return AdvisoryPackagePrivate::compare(*(first.private_pkg.get()), *(second.private_pkg.get()));
}
bool AdvisoryPackage::comparePackageNameArch(const AdvisoryPackage & adv_pkg, const rpm::Package & pkg) {
    return AdvisoryPackagePrivate::comparePackageNameArch(*(adv_pkg.private_pkg.get()), pkg);
}

// AdvisoryPackagePrivate
AdvisoryPackage::AdvisoryPackagePrivate::AdvisoryPackagePrivate(Base & base, Id advisory, Id name, Id evr, Id arch, const char * filename)
    : base(&base)
    , advisory(advisory)
    , name(name)
    , evr(evr)
    , arch(arch)
    , filename(filename)
{}

std::string AdvisoryPackage::AdvisoryPackagePrivate::get_name() const {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, name);
}

std::string AdvisoryPackage::AdvisoryPackagePrivate::get_version() const {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    const char * evr_str = pool_id2str(pool, evr);
    libdnf::rpm::Nevra nevra;
    nevra.parse(evr_str, libdnf::rpm::Nevra::Form::EVR);
    return nevra.get_version();
}

std::string AdvisoryPackage::AdvisoryPackagePrivate::get_evr() const {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, evr);
}

int AdvisoryPackage::AdvisoryPackagePrivate::get_advisory() const {
    return advisory;
}

std::string AdvisoryPackage::AdvisoryPackagePrivate::get_arch() const {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, arch);
}

bool AdvisoryPackage::AdvisoryPackagePrivate::compare(const AdvisoryPackagePrivate & first, const AdvisoryPackagePrivate & second) {
    if (first.name != second.name)
        return first.name < second.name;
    if (first.arch != second.arch)
        return first.arch < second.arch;
    return first.evr < second.evr;
}

bool AdvisoryPackage::AdvisoryPackagePrivate::comparePackageNameArch(const AdvisoryPackagePrivate & adv_pkg, const rpm::Package & pkg) {
    auto & solv_sack = adv_pkg.base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    Solvable *s = libdnf::rpm::solv::get_solvable(pool, pkg.get_id());

    if (adv_pkg.name != s->name)
        return adv_pkg.name < s->name;
    return adv_pkg.arch < s->arch;
}


}  // namespace libdnf
