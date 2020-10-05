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

#ifndef LIBDNF_ADVISORY_ADVISORY_MODULE_PRIVATE_HPP
#define LIBDNF_ADVISORY_ADVISORY_MODULE_PRIVATE_HPP

#include "libdnf/logger/logger.hpp"
#include "libdnf/utils/utils.hpp"
#include "libdnf/base/base.hpp"

#include <solv/chksum.h>
#include <solv/repo.h>
#include <solv/util.h>

#include "libdnf/advisory/advisory_module.hpp"

#include "libdnf/rpm/solv_sack_impl.hpp"

namespace libdnf {

class AdvisoryModule::AdvisoryModulePrivate {
public:

private:
    friend class AdvisoryCollection;
    friend AdvisoryModule;

    explicit AdvisoryModulePrivate(Base & base, Id advisory, Id name, Id stream, Id version, Id context, Id arch);
    explicit AdvisoryModulePrivate() = default;

    Base * base;
    Id advisory;

    Id name;
    Id stream;
    Id version;
    Id context;
    Id arch;
};

}  // namespace libdnf


#endif  // LIBDNF_ADVISORY_ADVISORY_MODULE_PRIVATE_HPP
