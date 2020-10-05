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

#ifndef LIBDNF_ADVISORY_ADVISORY_MODULE_HPP
#define LIBDNF_ADVISORY_ADVISORY_MODULE_HPP

#include <memory>
#include <vector>

namespace libdnf {

class Base;
class SolvSack;

struct AdvisoryModule {
public:
    AdvisoryModule(AdvisoryModule && src);
    ~AdvisoryModule();
    std::string get_name() const;
    std::string get_stream() const;
    std::string get_version() const;
    std::string get_context() const;
    std::string get_arch() const;

    //TODO(amatej): we might need (from original advisorymodules):
    //get_advisory
    //nsvcaEQ
    //getSack
private:
    friend class AdvisoryCollection;

    class AdvisoryModulePrivate;

    AdvisoryModule(AdvisoryModulePrivate * private_module);

    std::unique_ptr<AdvisoryModulePrivate> private_module;
};

}  // namespace libdnf

#endif
