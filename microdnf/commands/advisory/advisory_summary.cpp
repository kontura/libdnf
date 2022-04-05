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


#include "advisory_summary.hpp"

#include "microdnf/context.hpp"

#include <libdnf-cli/output/advisorysummary.hpp>
#include <libdnf/rpm/package_query.hpp>

#include <filesystem>
#include <fstream>
#include <set>


namespace microdnf {


using namespace libdnf::cli;


AdvisorySummaryCommand::AdvisorySummaryCommand(Command & parent) : AdvisorySummaryCommand(parent, "summary") {}


AdvisorySummaryCommand::AdvisorySummaryCommand(Command & parent, const std::string & name)
    : AdvisorySummaryCommand(parent, name, "Print summary of advisories") {}

AdvisorySummaryCommand::AdvisorySummaryCommand(
    Command & parent, const std::string & name, const std::string & short_description)
    : Command(parent, name) {
    auto & ctx = static_cast<Context &>(get_session());
    auto & parser = ctx.get_argument_parser();

    auto & cmd = *get_argument_parser_command();
    cmd.set_short_description(short_description);

    all = std::make_unique<AdvisoryAllOption>(*this);
    available = std::make_unique<AdvisoryAvailableOption>(*this);
    installed = std::make_unique<AdvisoryInstalledOption>(*this);
    updates = std::make_unique<AdvisoryUpdatesOption>(*this);
    advisory_specs = std::make_unique<AdvisorySpecArguments>(*this);
    what_contains = std::make_unique<AdvisoryWhatcontainsOption>(*this);

    auto conflict_args = parser.add_conflict_args_group(std::unique_ptr<std::vector<ArgumentParser::Argument *>>(
        new std::vector<ArgumentParser::Argument *>{all->arg, available->arg, installed->arg, updates->arg}));

    all->arg->set_conflict_arguments(conflict_args);
    available->arg->set_conflict_arguments(conflict_args);
    installed->arg->set_conflict_arguments(conflict_args);
    updates->arg->set_conflict_arguments(conflict_args);
}

void AdvisorySummaryCommand::add_running_kernel_packages(
    libdnf::Base & base, libdnf::rpm::PackageQuery & package_query) {
    auto kernel = base.get_rpm_package_sack()->get_running_kernel();
    if (kernel.get_id().id > 0) {
        libdnf::rpm::PackageQuery kernel_query(base);
        kernel_query.filter_sourcerpm({kernel.get_sourcerpm()});
        kernel_query.filter_installed();
        package_query |= kernel_query;
    }
}

void AdvisorySummaryCommand::process_queries(
    Context & ctx, libdnf::advisory::AdvisoryQuery & advisories, libdnf::rpm::PackageQuery & packages) {
    std::string mode;

    if (all->get_value()) {
        packages.filter_installed();
        advisories.filter_packages(packages, libdnf::sack::QueryCmp::LTE);
        auto advisory_query_not_installed = libdnf::advisory::AdvisoryQuery(ctx.base);
        advisory_query_not_installed.filter_packages(packages, libdnf::sack::QueryCmp::GT);
        advisories |= advisory_query_not_installed;
        mode = _("All");
    } else if (installed->get_value()) {
        packages.filter_installed();
        advisories.filter_packages(packages, libdnf::sack::QueryCmp::LTE);
        mode = _("Installed");
    } else if (updates->get_value()) {
        packages.filter_upgradable();
        advisories.filter_packages(packages, libdnf::sack::QueryCmp::GT);
        mode = _("Updates");
    } else {  // available is the default
        packages.filter_installed();
        packages.filter_latest_evr();

        add_running_kernel_packages(ctx.base, packages);

        advisories.filter_packages(packages, libdnf::sack::QueryCmp::GT);
        mode = _("Available");
    }

    print(advisories, mode);
}

void AdvisorySummaryCommand::print(const libdnf::advisory::AdvisoryQuery & advisories, std::string & mode) {
    libdnf::cli::output::print_advisorysummary_table(advisories, mode);
}

void AdvisorySummaryCommand::run() {
    auto & ctx = static_cast<Context &>(get_session());

    ctx.load_repos(true, libdnf::repo::Repo::LoadFlags::UPDATEINFO);

    libdnf::rpm::PackageQuery package_query(ctx.base);
    auto package_specs_strs = what_contains->get_value();
    // Filter packages by name patterns if given
    if (package_specs_strs.size() > 0) {
        package_query.filter_name(package_specs_strs, libdnf::sack::QueryCmp::IGLOB);
    }

    auto advisories = libdnf::advisory::AdvisoryQuery(ctx.base);
    auto advisory_specs_strs = advisory_specs->get_value();
    // Filter advisories by patterns if given
    if (advisory_specs_strs.size() > 0) {
        advisories.filter_name(advisory_specs_strs, libdnf::sack::QueryCmp::IGLOB);
    }

    process_queries(ctx, advisories, package_query);
}

}  // namespace microdnf
