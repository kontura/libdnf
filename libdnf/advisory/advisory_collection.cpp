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

//TODO(amatej): fix includes to have only neccassary
#include "libdnf/logger/logger.hpp"
#include "libdnf/utils/utils.hpp"
#include "libdnf/base/base.hpp"

#include <solv/chksum.h>
#include <solv/repo.h>
#include <solv/util.h>

#include "libdnf/rpm/solv_sack_impl.hpp"

#include "libdnf/advisory/advisory_collection.hpp"
#include "advisory_package_private.hpp"
#include "advisory_module_private.hpp"

namespace libdnf {

AdvisoryCollection::AdvisoryCollection(Base & base, AdvisoryId advisory, int index) : base(base), advisory(advisory), index(index) {}

bool AdvisoryCollection::is_applicable() const {
    //TODO(amatej): check if collection is applicable
    return true;
}

std::vector<AdvisoryPackage> AdvisoryCollection::get_packages(bool with_filemanes) const {
    std::vector<AdvisoryPackage> output;

    Dataiterator di;
    const char * filename = nullptr;
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    int count = 0;

    dataiterator_init(&di, pool, 0, advisory.id, UPDATE_COLLECTIONLIST, 0, 0);
    while (dataiterator_step(&di)) {
        dataiterator_setpos(&di);
        if (count == index) {

            Dataiterator di_inner;
            dataiterator_init(&di_inner, pool, 0, SOLVID_POS, UPDATE_COLLECTION, 0, 0);
            while (dataiterator_step(&di_inner)) {
                dataiterator_setpos(&di_inner);
                Id name = pool_lookup_id(pool, SOLVID_POS, UPDATE_COLLECTION_NAME);
                Id evr = pool_lookup_id(pool, SOLVID_POS, UPDATE_COLLECTION_EVR);
                Id arch = pool_lookup_id(pool, SOLVID_POS, UPDATE_COLLECTION_ARCH);
                if (with_filemanes) {
                    filename = pool_lookup_str(pool, SOLVID_POS, UPDATE_COLLECTION_FILENAME);
                }
                output.emplace_back(AdvisoryPackage(new AdvisoryPackage::AdvisoryPackagePrivate(base, advisory.id, name, evr, arch, filename)));
            }
            dataiterator_free(&di_inner);
            break;

        }
        count++;
    }
    dataiterator_free(&di);

    return output;
}

std::vector<AdvisoryModule> AdvisoryCollection::get_modules() const {
    std::vector<AdvisoryModule> output;

    Dataiterator di;
    auto & solv_sack = base.get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    int count = 0;

    dataiterator_init(&di, pool, 0, advisory.id, UPDATE_COLLECTIONLIST, 0, 0);
    while (dataiterator_step(&di)) {
        dataiterator_setpos(&di);
        if (count == index) {

            Dataiterator di_inner;
            dataiterator_init(&di_inner, pool, 0, SOLVID_POS, UPDATE_MODULE, 0, 0);
            while (dataiterator_step(&di_inner)) {
                dataiterator_setpos(&di_inner);
                Id name = pool_lookup_id(pool, SOLVID_POS, UPDATE_MODULE_NAME);
                Id stream = pool_lookup_id(pool, SOLVID_POS, UPDATE_MODULE_STREAM);
                Id version = pool_lookup_id(pool, SOLVID_POS, UPDATE_MODULE_VERSION);
                Id context = pool_lookup_id(pool, SOLVID_POS, UPDATE_MODULE_CONTEXT);
                Id arch = pool_lookup_id(pool, SOLVID_POS, UPDATE_MODULE_ARCH);
                output.emplace_back(AdvisoryModule(new AdvisoryModule::AdvisoryModulePrivate(base, advisory.id, name, stream, version, context, arch)));
            }
            dataiterator_free(&di_inner);
            break;

        }
        count++;
    }
    dataiterator_free(&di);

    return output;
}

}  // namespace libdnf
