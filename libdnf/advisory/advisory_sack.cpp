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

#include "libdnf/advisory/advisory_sack.hpp"

#include "libdnf/base/base.hpp"
#include <solv/util.h>
#include <solv/repo.h>

#include "libdnf/rpm/solv_sack_impl.hpp"

namespace libdnf {

AdvisoryWeakPtr AdvisorySack::new_advisory(AdvisoryId id) {
    auto advisory = std::make_unique<Advisory>(Advisory(id, *base));
    return add_item_with_return(std::move(advisory));
}

void AdvisorySack::load_advisories_from_solvsack() {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    Dataiterator di;

    dataiterator_init(&di, pool, 0, 0, 0, 0, 0);
    //TODO(amatej): Is there no way to iterate directly on advisories (UPDATE_COLLECTION is a package no?)
    dataiterator_prepend_keyname(&di, UPDATE_COLLECTION);

    while (dataiterator_step(&di)) {
        new_advisory(AdvisoryId(di.solvid));
        dataiterator_skip_solvable(&di);
    }
    dataiterator_free(&di);

}

}  // namespace libdnf
