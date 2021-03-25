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

#ifndef LIBDNF_ADVISORY_ADVISORY_QUERY_HPP
#define LIBDNF_ADVISORY_ADVISORY_QUERY_HPP

#include "libdnf/common/sack/query.hpp"
#include "libdnf/rpm/package.hpp"
#include "libdnf/utils/weak_ptr.hpp"

#include "advisory_reference.hpp"
#include "advisory_package.hpp"
#include "advisory_collection.hpp"
#include "advisory.hpp"

namespace libdnf {

/// Weak pointer to an advisory. AdvisoryWeakPtr does not own the advisory (ptr_owner = false).
/// Advisories are owned by AdvisorySack.
using AdvisoryWeakPtr = WeakPtr<Advisory, false>;

class AdvisoryQuery : public libdnf::sack::Query<AdvisoryWeakPtr> {
public:
#ifndef SWIG
    using Query<AdvisoryWeakPtr>::Query;
#endif
    AdvisoryQuery & ifilter_id(sack::QueryCmp cmp, int64_t id);
    AdvisoryQuery & ifilter_id(sack::QueryCmp cmp, const std::vector<int64_t> & ids);

    AdvisoryQuery & ifilter_name(sack::QueryCmp cmp, const std::string & pattern);
    AdvisoryQuery & ifilter_name(sack::QueryCmp cmp, const std::vector<std::string> & patterns);

    AdvisoryQuery & ifilter_type(sack::QueryCmp cmp, const Advisory::Type type);
    AdvisoryQuery & ifilter_type(sack::QueryCmp cmp, const std::vector<Advisory::Type> & types);

    //This could just wrap package_set
    AdvisoryQuery & ifilter_package(sack::QueryCmp cmp, const libdnf::rpm::Package & package);
    std::vector<AdvisoryPackage> get_advisory_packages(sack::QueryCmp cmp, const libdnf::rpm::PackageSet & package_set);

    // Filter out advisories that don't contain at least one package fulfilling the condition cmp
    AdvisoryQuery & ifilter_package_set(sack::QueryCmp cmp, const libdnf::rpm::PackageSet & package_set);

    AdvisoryQuery & ifilter_CVE(sack::QueryCmp cmp, const std::string & pattern);
    AdvisoryQuery & ifilter_CVE(sack::QueryCmp cmp, const std::vector<std::string> & patterns);
    AdvisoryQuery & ifilter_bug(sack::QueryCmp cmp, const std::string & pattern);
    AdvisoryQuery & ifilter_bug(sack::QueryCmp cmp, const std::vector<std::string> & patterns);
    AdvisoryQuery & ifilter_severity(sack::QueryCmp cmp, const std::string & pattern);
    AdvisoryQuery & ifilter_severity(sack::QueryCmp cmp, const std::vector<std::string> & patterns);

    //Replaces isAdvisoryApplicable
    AdvisoryQuery & ifilter_applicable(bool applicable);

    std::vector<AdvisoryPackage> get_advisory_packages();
    std::vector<AdvisoryPackage> get_advisory_packages_from_applicable_collections();
    std::vector<std::string> get_advisory_pkgs_nevras();

private:
    struct F {
        static int64_t id(const AdvisoryWeakPtr & obj) { return (int64_t) obj->get_id().id; }
        static std::string name(const AdvisoryWeakPtr & obj) { return obj->get_name(); }
        static int64_t type(const AdvisoryWeakPtr & obj) { return (int64_t) obj->get_type(); }
        static std::vector<std::string> cve(const AdvisoryWeakPtr & obj) {
            //TODO(amatej): this could be done better
            std::vector<std::string> out;
            for(const auto & value: obj->get_references("cve")) {
                out.push_back(value.get_id());
            }

            return out;
        }
        static std::vector<std::string> bug(const AdvisoryWeakPtr & obj) {
            //TODO(amatej): this could be done better
            std::vector<std::string> out;
            for(const auto & value: obj->get_references("bugzilla")) {
                out.push_back(value.get_id());
            }

            return out;
        }
        static std::string severity(const AdvisoryWeakPtr & obj) { return std::string(obj->get_severity()); }
        static bool applicable(const AdvisoryWeakPtr & obj) { return obj->is_applicable(); }
    };
};

inline AdvisoryQuery & AdvisoryQuery::ifilter_id(sack::QueryCmp cmp, int64_t id) {
    ifilter(F::id, cmp, id);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_id(sack::QueryCmp cmp, const std::vector<int64_t> & ids) {
    ifilter(F::id, cmp, ids);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_name(sack::QueryCmp cmp, const std::string & pattern) {
    ifilter(F::name, cmp, pattern);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_name(sack::QueryCmp cmp, const std::vector<std::string> & patterns) {
    ifilter(F::name, cmp, patterns);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_type(sack::QueryCmp cmp, const Advisory::Type type) {
    ifilter(F::type, cmp, (int64_t) type);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_type(sack::QueryCmp cmp, const std::vector<Advisory::Type> & types) {
    std::vector<int64_t> int_types;
    int_types.reserve(types.size());
    for(std::size_t i = 0; i < types.size(); ++i) {
        int_types[i] = (int64_t) types[i];
    }
    ifilter(F::type, cmp, int_types);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_CVE(sack::QueryCmp cmp, const std::string & pattern) {
    ifilter(F::cve, cmp, pattern);
    return *this;
}
inline AdvisoryQuery & AdvisoryQuery::ifilter_CVE(sack::QueryCmp cmp, const std::vector<std::string> & patterns) {
    ifilter(F::cve, cmp, patterns);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_bug(sack::QueryCmp cmp, const std::string & pattern) {
    ifilter(F::bug, cmp, pattern);
    return *this;
}
inline AdvisoryQuery & AdvisoryQuery::ifilter_bug(sack::QueryCmp cmp, const std::vector<std::string> & patterns) {
    ifilter(F::bug, cmp, patterns);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_severity(sack::QueryCmp cmp, const std::string & pattern) {
    ifilter(F::severity, cmp, pattern);
    return *this;
}
inline AdvisoryQuery & AdvisoryQuery::ifilter_severity(sack::QueryCmp cmp, const std::vector<std::string> & patterns) {
    ifilter(F::severity, cmp, patterns);
    return *this;
}

inline AdvisoryQuery & AdvisoryQuery::ifilter_applicable(bool applicable) {
    ifilter(F::applicable, sack::QueryCmp::EQ, applicable);
    return *this;
}

//TODO(amatej): maybe rename to get_advisory_packages_sorted
inline std::vector<AdvisoryPackage> AdvisoryQuery::get_advisory_packages() {
    std::vector<AdvisoryPackage> out;
    for (auto advisory = get_data().begin(); advisory != get_data().end();++advisory) {
        auto collections = (*advisory)->get_collections();

        for(const auto& collection: collections) {
            collection.get_packages(out);
        }
    }

    std::sort(out.begin(), out.end(), AdvisoryPackage::compare);

    return out;
}

inline std::vector<std::string> AdvisoryQuery::get_advisory_pkgs_nevras() {
    std::vector<std::string> nevras;
    for (auto advisory = get_data().begin(); advisory != get_data().end();++advisory) {
        auto collections = (*advisory)->get_collections();

        for(const auto & collection: collections) {
            std::vector<AdvisoryPackage> packages;
            collection.get_packages(packages);
            for (const auto & pkg: packages) {
                nevras.push_back(pkg.get_name() + "-" + pkg.get_evr() + "." + pkg.get_arch());
            }

        }
    }

    return nevras;
}


}  // namespace libdnf

#endif
