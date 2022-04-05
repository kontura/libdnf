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


#ifndef MICRODNF_COMMANDS_ADVISORY_ADVISORY_SUMMARY_HPP
#define MICRODNF_COMMANDS_ADVISORY_ADVISORY_SUMMARY_HPP

#include "arguments.hpp"
#include "microdnf/context.hpp"

#include "libdnf/advisory/advisory_query.hpp"

#include <libdnf-cli/session.hpp>

#include <memory>
#include <vector>


namespace microdnf {


class AdvisorySummaryCommand : public libdnf::cli::session::Command {
public:
    explicit AdvisorySummaryCommand(Command & parent);
    void run() override;
    virtual void print(const libdnf::advisory::AdvisoryQuery & advisories, std::string & mode);
    virtual void process_queries(
        Context & ctx, libdnf::advisory::AdvisoryQuery & advisories, libdnf::rpm::PackageQuery & packages);

    std::unique_ptr<AdvisoryAvailableOption> available{nullptr};
    std::unique_ptr<AdvisoryInstalledOption> installed{nullptr};
    std::unique_ptr<AdvisoryAllOption> all{nullptr};
    std::unique_ptr<AdvisoryUpdatesOption> updates{nullptr};
    std::unique_ptr<AdvisorySpecArguments> advisory_specs{nullptr};

protected:
    void add_running_kernel_packages(libdnf::Base & base, libdnf::rpm::PackageQuery & package_query);

    // to be used by an alias command only
    explicit AdvisorySummaryCommand(Command & parent, const std::string & name);
    explicit AdvisorySummaryCommand(Command & parent, const std::string & name, const std::string & short_description);
};


}  // namespace microdnf


#endif  // MICRODNF_COMMANDS_ADVISORY_ADVISORY_SUMMARY_HPP
