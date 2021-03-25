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

#ifndef LIBDNF_ADVISORY_ADVISORY_SACK_HPP
#define LIBDNF_ADVISORY_ADVISORY_SACK_HPP

#include "advisory.hpp"
#include "advisory_query.hpp"

#include "libdnf/common/sack/sack.hpp"
#include "libdnf/logger/logger.hpp"

namespace libdnf {

class Base;

class AdvisorySack : public sack::Sack<Advisory, AdvisoryQuery> {
public:
    explicit AdvisorySack(Base & base) : base(&base) {}

    void load_advisories_from_solvsack();

private:

    /// Creates new advisory and add it into AdvisorySack
    AdvisoryWeakPtr new_advisory(AdvisoryId id);

    Base * base;
};

}  // namespace libdnf

#endif
