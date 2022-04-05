/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 2.1 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/


#include "libdnf-cli/output/advisorysummary.hpp"

#include "libdnf-cli/output/key_value_table.hpp"

#include <iostream>

namespace libdnf::cli::output {


void print_advisorysummary_table(const libdnf::advisory::AdvisoryQuery & advisories, const std::string & mode) {
    KeyValueTable output_table;
    std::cout << mode << " advisory information summary:" << std::endl;

    auto bugfixes = advisories;
    bugfixes.filter_type("bugfix");

    auto enhancements = advisories;
    enhancements.filter_type("enhancement");

    auto securities = advisories;
    securities.filter_type("security");

    auto security_critical = libdnf::advisory::AdvisoryQuery(securities);
    security_critical.filter_severity("Critical");
    auto security_important = libdnf::advisory::AdvisoryQuery(securities);
    security_important.filter_severity("Important");
    auto security_moderate = libdnf::advisory::AdvisoryQuery(securities);
    security_moderate.filter_severity("Moderate");
    auto security_low = libdnf::advisory::AdvisoryQuery(securities);
    security_low.filter_severity("Low");
    auto security_none = libdnf::advisory::AdvisoryQuery(securities);
    security_none.filter_severity("None");

    auto others = advisories;
    others -= bugfixes;
    others -= enhancements;
    others -= securities;

    auto security_row = output_table.add_line("Security", securities.size(), nullptr);
    output_table.add_line("Critical", security_critical.size(), nullptr, security_row);
    output_table.add_line("Important", security_important.size(), nullptr, security_row);
    output_table.add_line("Moderate", security_moderate.size(), nullptr, security_row);
    output_table.add_line("Low", security_low.size(), nullptr, security_row);
    output_table.add_line("None", security_none.size(), nullptr, security_row);

    output_table.add_line("Bugfix", bugfixes.size(), nullptr);
    output_table.add_line("Enhancement", enhancements.size(), nullptr);

    output_table.add_line("Others", others.size(), nullptr);

    output_table.print();
}


}  // namespace libdnf::cli::output
