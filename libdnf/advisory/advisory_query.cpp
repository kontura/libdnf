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

#include "libdnf/advisory/advisory_query.hpp"

#include <solv/util.h>
#include <solv/repo.h>
#include <solv/evr.h>

#include "libdnf/rpm/package_set.hpp"
#include "libdnf/rpm/solv_sack_impl.hpp"

namespace libdnf {

// What we need:
// 1. get all applicable advisiories for a pkg (name, arch) -> while having a condition for nevras >,<,= ((THIS IS A FILTER ON Advisory_sack))
// 2. from a packageset (query) get all applicable advisory packages while comparing nevras >,<,= ((THIS IS A FILTER ON Package_sack, BASICALLY FILTER ONE PKG SET BY ANOTHER GIVEN COMPARATOR))
// 3. Query::Impl::filterAdvisory:
//     -> filter advisories by name,bug,cve,severity.. (DONE)
//     -> get all applicable packages from those advs  (DONE)
//       -> (( intersect two packageset in a way specified by comparator (same as 2) ))
//       -> if special HY_EQG comparator used:
//        -->> 1. HY_UPGRADE: remove all that have the same or higher version installed ((THIS IS A PACKAGE QUERY ON THE INPUT))
//             2. HY_EQG: Get packages that are equal and if none get the first higher  ((DIFFERENT WAY TO FILTER ONE PACKAGE SET BY ANOTHER))



AdvisoryQuery & AdvisoryQuery::ifilter_package_set(sack::QueryCmp cmp, const libdnf::rpm::PackageSet & package_set) {
    //check cmp is valid, only numbers comparator
    std::vector<AdvisoryPackage> pkgs = get_advisory_packages();
    std::vector<AdvisoryPackage> after_filter;
    if (pkgs.size() == 0) {
        return *this;
    }

    auto solv_sack = package_set.get_sack();
    Pool * pool = solv_sack->p_impl->get_pool();

    for (libdnf::rpm::PackageSet::iterator package = package_set.begin(); package != package_set.end(); package++) {
        auto low = std::lower_bound(pkgs.begin(), pkgs.end(), *package, AdvisoryPackage::comparePackageNameArch);

        //TODO(amatej): originally in dnf4 we compared id, that must have been faster
        while (low != pkgs.end() && low->get_name() == (*package).get_name() && low->get_arch() == (*package).get_arch()) {

            int libsolv_cmp = pool_evrcmp_str(pool, low->get_evr().c_str(), (*package).get_evr().c_str(), EVRCMP_COMPARE);

            if (((libsolv_cmp > 0) && (cmp == sack::QueryCmp::GT || cmp == sack::QueryCmp::GTE)) ||
                ((libsolv_cmp < 0) && (cmp == sack::QueryCmp::LT || cmp == sack::QueryCmp::LTE)) ||
                ((libsolv_cmp == 0) && (cmp == sack::QueryCmp::EXACT || cmp == sack::QueryCmp::LTE || cmp == sack::QueryCmp::GTE))) {
                after_filter.push_back(*low);
            }
            ++low;
        }
    }

    //after_filter contains just advisoryPackages which comply to condition with package_set so we want only their advisories
    //This should be a set, its likely worth it
    std::vector<int64_t> ids;
    for (AdvisoryPackage pkg : after_filter) {
        ids.push_back(pkg.get_advisory());
    }

    ifilter_id(sack::QueryCmp::EQ, ids);

    return *this;
}

AdvisoryQuery & AdvisoryQuery::ifilter_package(sack::QueryCmp cmp, const libdnf::rpm::Package & package) {
    libdnf::rpm::PackageSet ps(package.get_sack());
    ps.add(package);
    ifilter_package_set(cmp, ps);
    return *this;
}


std::vector<AdvisoryPackage> AdvisoryQuery::get_advisory_packages(sack::QueryCmp cmp, const libdnf::rpm::PackageSet & package_set) {
    //check cmp is valid, only numbers comparator
    std::vector<AdvisoryPackage> pkgs = get_advisory_packages();
    std::vector<AdvisoryPackage> after_filter;
    if (pkgs.size() == 0) {
        return after_filter;
    }

    auto solv_sack = package_set.get_sack();
    Pool * pool = solv_sack->p_impl->get_pool();

    for (libdnf::rpm::PackageSet::iterator package = package_set.begin(); package != package_set.end(); package++) {
        auto low = std::lower_bound(pkgs.begin(), pkgs.end(), *package, AdvisoryPackage::comparePackageNameArch);

        //TODO(amatej): originally in dnf4 we compared id, that must have been faster
        while (low != pkgs.end() && low->get_name() == (*package).get_name() && low->get_arch() == (*package).get_arch()) {

            int libsolv_cmp = pool_evrcmp_str(pool, low->get_evr().c_str(), (*package).get_evr().c_str(), EVRCMP_COMPARE);

            if (((libsolv_cmp > 0) && ((uint32_t)(cmp & sack::QueryCmp::GT) || (uint32_t)(cmp & sack::QueryCmp::GTE))) ||
                ((libsolv_cmp < 0) && ((uint32_t)(cmp & sack::QueryCmp::LT) || (uint32_t)(cmp & sack::QueryCmp::LTE))) ||
                ((libsolv_cmp == 0) && ((uint32_t)(cmp & sack::QueryCmp::EXACT) || (uint32_t)(cmp & sack::QueryCmp::LTE) || (uint32_t)(cmp & sack::QueryCmp::GTE)))) {
                after_filter.push_back(*low);
            }
            ++low;
        }
    }

    //after_filter contains just advisoryPackages which comply to condition with package_set
    return after_filter;
}

}  // namespace libdnf
