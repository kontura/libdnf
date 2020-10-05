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

#include "advisory_module_private.hpp"

#include "libdnf/rpm/solv_sack_impl.hpp"

#include "libdnf/advisory/advisory_module.hpp"

namespace libdnf {

AdvisoryModule::AdvisoryModule(AdvisoryModulePrivate * private_module)
    : private_module(private_module)
{}

AdvisoryModule::AdvisoryModulePrivate::AdvisoryModulePrivate(Base & base, Id advisory, Id name, Id stream, Id version, Id context, Id arch)
    : base(&base)
    , advisory(advisory)
    , name(name)
    , stream(stream)
    , version(version)
    , context(context)
    , arch(arch)
{}

AdvisoryModule::AdvisoryModule(AdvisoryModule && src) : private_module(new AdvisoryModulePrivate) { private_module.swap(src.private_module); }

AdvisoryModule::~AdvisoryModule() = default;


std::string AdvisoryModule::get_name() const {
    auto & solv_sack = private_module->base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, private_module->name);
}

std::string AdvisoryModule::get_stream() const {
    auto & solv_sack = private_module->base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, private_module->stream);
}
std::string AdvisoryModule::get_version() const {
    auto & solv_sack = private_module->base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, private_module->version);
}
std::string AdvisoryModule::get_context() const {
    auto & solv_sack = private_module->base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, private_module->context);
}
std::string AdvisoryModule::get_arch() const {
    auto & solv_sack = private_module->base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();
    return pool_id2str(pool, private_module->arch);
}


}  // namespace libdnf
