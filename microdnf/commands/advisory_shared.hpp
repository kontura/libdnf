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


#ifndef MICRODNF_COMMANDS_ARGUMENTS_HPP
#define MICRODNF_COMMANDS_ARGUMENTS_HPP


#include "utils/bgettext/bgettext-lib.h"
#include "utils/string.hpp"

#include <libdnf-cli/session.hpp>

#include "libdnf/base/base_weak.hpp"

#include <libdnf/advisory/advisory_query.hpp>

#include <optional>


namespace microdnf {

inline std::optional<libdnf::advisory::AdvisoryQuery> advisory_query_from_cli_input(
    libdnf::Base & base,
    std::vector<std::string> advisory_names,
    std::vector<std::string> advisory_types,
    std::vector<std::string> advisory_severities,
    std::vector<std::string> advisory_bzs,
    std::vector<std::string> advisory_cves) {
    if (advisory_types.size() > 0 || advisory_severities.size() > 0 || advisory_names.size() > 0 ||
        advisory_bzs.size() > 0 || advisory_cves.size() > 0) {
        auto advisories = libdnf::advisory::AdvisoryQuery(base);
        // Filter by advisory name
        if (advisory_names.size() > 0) {
            advisories.filter_name(advisory_names);
        }

        // Filter by advisory type
        if (advisory_types.size() > 0) {
            advisories.filter_type(advisory_types);
        }

        // Filter by advisory severity
        if (advisory_severities.size() > 0) {
            advisories.filter_severity(advisory_severities);
        }

        // Filter by advisory bz
        if (advisory_bzs.size() > 0) {
            advisories.filter_reference(advisory_bzs, libdnf::sack::QueryCmp::EQ, {"bugzilla"});
        }

        // Filter by advisory cve
        if (advisory_cves.size() > 0) {
            advisories.filter_reference(advisory_cves, libdnf::sack::QueryCmp::EQ, {"cve"});
        }

        return advisories;
    }

    return std::nullopt;
}

class AdvisoryNameFilterOption : public libdnf::cli::session::StringListOption {
public:
    explicit AdvisoryNameFilterOption(libdnf::cli::session::Command & command)
        : StringListOption(
              command,
              "advisory-name-filter",
              '\0',
              _("Consider only content contained in advisories with specified name. List option."),
              _("ADVISORY_NAME,...")) {}
};


class AdvisoryTypeFilterOption : public libdnf::cli::session::StringListOption {
public:
    explicit AdvisoryTypeFilterOption(libdnf::cli::session::Command & command)
        : StringListOption(
              command,
              "advisory-type-filter",
              '\0',
              _("Consider only content contained in advisories with specified type. List option. Can be \"bugfix\", "
                "\"security\", \"enhancement\", \"newpackage\"."),
              _("ADVISORY_TYPE,..."),
              "bugfix|security|enhancement|newpackage",
              true) {}

    std::vector<std::string> get_value() const {
        auto v = StringListOption::get_value();
        std::transform(v.begin(), v.end(), v.begin(), libdnf::utils::string::tolower);
        return v;
    }
};


class AdvisorySeverityFilterOption : public libdnf::cli::session::StringListOption {
public:
    explicit AdvisorySeverityFilterOption(libdnf::cli::session::Command & command)
        : StringListOption(
              command,
              "advisory-severity-filter",
              '\0',
              _("Consider only content contained in advisories with specified severity. List option. Can be "
                "\"critical\", \"important\", \"moderate\", \"low\", \"none\"."),
              _("ADVISORY_SEVERITY,..."),
              "critical|important|moderate|low|none",
              true) {}

    std::vector<std::string> get_value() const {
        auto v = StringListOption::get_value();
        std::transform(v.begin(), v.end(), v.begin(), [](std::string c) -> std::string {
            c = libdnf::utils::string::tolower(c);
            c[0] = static_cast<char>(std::toupper(c[0]));
            return c;
        });

        return v;
    }
};

class AdvisoryBzFilterOption : public libdnf::cli::session::StringListOption {
public:
    explicit AdvisoryBzFilterOption(libdnf::cli::session::Command & command)
        : StringListOption(
              command,
              "advisory-bz-filter",
              '\0',
              _("Consider only content contained in advisories that fix a Bugzilla ID, Eg. 123123. List option."),
              _("BUGZILLA_ID,...")) {}
};

class AdvisoryCveFilterOption : public libdnf::cli::session::StringListOption {
public:
    explicit AdvisoryCveFilterOption(libdnf::cli::session::Command & command)
        : StringListOption(
              command,
              "advisory-cve-filter",
              '\0',
              _("Consider only content contained in advisories that fix a CVE (Common Vulnerabilities and Exposures) "
                "ID, Eg. CVE-2201-0123. List option."),
              _("BUGZILLA_ID,...")) {}
};


}  // namespace microdnf


#endif  // MICRODNF_COMMANDS_ARGUMENTS_HPP
