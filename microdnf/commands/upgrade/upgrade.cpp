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


#include "upgrade.hpp"

#include "microdnf/context.hpp"

#include "libdnf-cli/output/transaction_table.hpp"

#include <libdnf/base/goal.hpp>
#include <libdnf/conf/option_string.hpp>
#include <libdnf/rpm/package.hpp>
#include <libdnf/rpm/package_query.hpp>
#include <libdnf/rpm/package_set.hpp>
#include <libdnf/rpm/transaction.hpp>

#include <filesystem>
#include <iostream>


namespace fs = std::filesystem;


namespace microdnf {


using namespace libdnf::cli;


UpgradeCommand::UpgradeCommand(Command & parent) : UpgradeCommand(parent, "upgrade") {}


UpgradeCommand::UpgradeCommand(Command & parent, const std::string & name) : Command(parent, name) {
    auto & ctx = static_cast<Context &>(get_session());
    auto & parser = ctx.get_argument_parser();

    auto & cmd = *get_argument_parser_command();
    cmd.set_short_description("Upgrade software");

    minimal = dynamic_cast<libdnf::OptionBool *>(
        parser.add_init_value(std::unique_ptr<libdnf::OptionBool>(new libdnf::OptionBool(false))));
    auto minimal_opt = parser.add_new_named_arg("minimal");
    minimal_opt->set_long_name("minimal");
    // TODO(dmach): Explain how this relates to options such as --security, --enhacement etc.
    minimal_opt->set_short_description(
        "Upgrade packages only to the lowest versions of packages that fix the problems affecting the system.");
    minimal_opt->set_const_value("true");
    minimal_opt->link_value(minimal);
    cmd.register_named_arg(minimal_opt);

    auto keys =
        parser.add_new_positional_arg("keys_to_match", ArgumentParser::PositionalArg::UNLIMITED, nullptr, nullptr);
    keys->set_short_description("List of keys to match");
    keys->set_parse_hook_func(
        [this]([[maybe_unused]] ArgumentParser::PositionalArg * arg, int argc, const char * const argv[]) {
            parse_add_specs(argc, argv, pkg_specs, pkg_file_paths);
            return true;
        });
    keys->set_complete_hook_func([&ctx](const char * arg) { return match_specs(ctx, arg, true, false, true, false); });

    advisory_name = std::make_unique<AdvisoryNameFilterOption>(*this);
    advisory_type = std::make_unique<AdvisoryTypeFilterOption>(*this);
    advisory_severity = std::make_unique<AdvisorySeverityFilterOption>(*this);
    advisory_bz = std::make_unique<AdvisoryBzFilterOption>(*this);
    advisory_cve = std::make_unique<AdvisoryCveFilterOption>(*this);

    cmd.register_positional_arg(keys);
}


void UpgradeCommand::run() {
    auto & ctx = static_cast<Context &>(get_session());

    ctx.load_repos(true);

    std::vector<std::string> error_messages;
    const auto cmdline_packages = ctx.add_cmdline_packages(pkg_file_paths, error_messages);
    for (const auto & msg : error_messages) {
        std::cout << msg << std::endl;
    }

    std::cout << std::endl;

    libdnf::Goal goal(ctx.base);

    auto settings = libdnf::GoalJobSettings();

    std::vector<std::string> types = advisory_type->get_value();
    settings.advisory_filter_cmp = libdnf::sack::QueryCmp::GTE;
    if (minimal->get_value()) {
        if (types.empty()) {
            types.push_back("security");
            types.push_back("bugfix");
            types.push_back("enhancement");
        }
        settings.advisory_filter_cmp = libdnf::sack::QueryCmp::EQ;
    }

    auto advisories = advisory_query_from_cli_input(
        ctx.base,
        advisory_name->get_value(),
        types,
        advisory_severity->get_value(),
        advisory_bz->get_value(),
        advisory_cve->get_value());
    if (advisories.has_value()) {
        settings.advisory_filter = advisories;
    }

    if (pkg_specs.empty() && pkg_file_paths.empty()) {
        goal.add_rpm_upgrade(settings);
    } else {
        for (const auto & pkg : cmdline_packages) {
            goal.add_rpm_upgrade(pkg, settings);
        }
        for (const auto & spec : pkg_specs) {
            goal.add_rpm_upgrade(spec, settings);
        }
    }

    auto transaction = goal.resolve(false);
    if (transaction.get_problems() != libdnf::GoalProblem::NO_PROBLEM) {
        return;
    }

    if (!libdnf::cli::output::print_transaction_table(transaction)) {
        return;
    }

    if (!userconfirm(ctx.base.get_config())) {
        std::cout << "Operation aborted." << std::endl;
        return;
    }

    ctx.download_and_run(transaction);
}


}  // namespace microdnf
