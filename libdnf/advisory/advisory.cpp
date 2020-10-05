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

#include <solv/chksum.h>
#include <solv/repo.h>
#include <solv/util.h>

#include "libdnf/rpm/solv_sack_impl.hpp"

#include "libdnf/advisory/advisory.hpp"
#include "libdnf/advisory/advisory_reference.hpp"
#include "libdnf/advisory/advisory_collection.hpp"


namespace libdnf {

Advisory::Advisory(AdvisoryId id, Base & base) : id(id), base(base) {}

const char * Advisory::get_name() const {
    const char *name;
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();

    name = pool_lookup_str(pool, id.id, SOLVABLE_NAME);
    size_t prefix_len = strlen("patch:");

    assert(strncmp("patch:", name, prefix_len) == 0);

    return name + prefix_len;
}

Advisory::Type Advisory::get_type() const {
    const char * type;
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    type = pool_lookup_str(pool, id.id, SOLVABLE_PATCHCATEGORY);

    //TODO(amatej): conversion function?
    if (type == NULL) {
        return Advisory::Type::UNKNOWN;
    }
    if (!strcmp (type, "bugfix")) {
        return Advisory::Type::BUGFIX;
    }
    if (!strcmp (type, "enhancement")){
        return Advisory::Type::ENHANCEMENT;
    }
    if (!strcmp (type, "security")){
        return Advisory::Type::SECURITY;
    }
    if (!strcmp (type, "newpackage")) {
        return Advisory::Type::NEWPACKAGE;
    }

    return Advisory::Type::UNKNOWN;
}

const char* Advisory::get_severity() const {
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();

    return pool_lookup_str(pool, id.id, UPDATE_SEVERITY);
}

AdvisoryId Advisory::get_id() const {
    return id;
}

std::vector<AdvisoryReference> Advisory::get_references(const char * type) const {
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();

    std::vector<AdvisoryReference> output;

    Dataiterator di;
    dataiterator_init(&di, pool, 0, id.id, UPDATE_REFERENCE, 0 ,0);

    for (int index = 0; dataiterator_step(&di); index++) {
        dataiterator_setpos(&di);
        if (!type || (strcmp(pool_lookup_str(pool, SOLVID_POS, UPDATE_REFERENCE_TYPE), type) == 0)) {
            output.emplace_back(AdvisoryReference(base, id, index));
        }
    }

    dataiterator_free(&di);
    return output;
}

std::vector<AdvisoryCollection> Advisory::get_collections() const {
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();

    std::vector<AdvisoryCollection> output;

    Dataiterator di;
    dataiterator_init(&di, pool, 0, id.id, UPDATE_COLLECTIONLIST, 0 ,0);

    for (int index = 0; dataiterator_step(&di); index++) {
        dataiterator_setpos(&di);
        output.emplace_back(AdvisoryCollection(base, id, index));
    }

    dataiterator_free(&di);

    return output;
}

bool Advisory::is_applicable() const {
    for(const auto & collection: get_collections()) {
        if (collection.is_applicable()) {
            return true;
        }
    }

    return false;
}

Advisory::~Advisory() = default;

}  // namespace libdnf
