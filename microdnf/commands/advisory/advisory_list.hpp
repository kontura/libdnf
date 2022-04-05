/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/


#ifndef MICRODNF_COMMANDS_ADVISORY_ADVISORY_LIST_HPP
#define MICRODNF_COMMANDS_ADVISORY_ADVISORY_LIST_HPP


#include "advisory_summary.hpp"
#include "arguments.hpp"

#include <libdnf-cli/session.hpp>
#include <libdnf/conf/option_bool.hpp>

#include <memory>
#include <vector>


namespace microdnf {


class AdvisoryListCommand : public AdvisorySummaryCommand {
public:
    explicit AdvisoryListCommand(Command & parent);
    void process_queries(
        Context & ctx, libdnf::advisory::AdvisoryQuery & advisories, libdnf::rpm::PackageQuery & packages) override;

protected:
    // to be used by an alias command only
    explicit AdvisoryListCommand(Command & parent, const std::string & name);
};


}  // namespace microdnf


#endif  // MICRODNF_COMMANDS_ADVISORY_ADVISORY_LIST_HPP
