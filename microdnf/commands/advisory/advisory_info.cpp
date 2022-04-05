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


#include "advisory_info.hpp"

#include "microdnf/context.hpp"

#include <libdnf-cli/output/advisoryinfo.hpp>
#include <libdnf/rpm/package_query.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>


namespace microdnf {


using namespace libdnf::cli;


AdvisoryInfoCommand::AdvisoryInfoCommand(Command & parent) : AdvisoryInfoCommand(parent, "info") {}


AdvisoryInfoCommand::AdvisoryInfoCommand(Command & parent, const std::string & name)
    : AdvisorySummaryCommand(parent, name, "Print details about advisories") {}

void AdvisoryInfoCommand::print(
    const libdnf::advisory::AdvisoryQuery & advisories, [[maybe_unused]] std::string & mode) {
    for (auto advisory : advisories) {
        libdnf::cli::output::AdvisoryInfo advisory_info;
        advisory_info.add_advisory(advisory);
        advisory_info.print();
        std::cout << std::endl;
    }
}


}  // namespace microdnf
