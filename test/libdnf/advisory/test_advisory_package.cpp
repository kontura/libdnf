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


#include "test_advisory_package.hpp"

#include "libdnf/rpm/package_set.hpp"
#include "libdnf/rpm/solv_query.hpp"

#include <filesystem>
#include <set>
#include <vector>


CPPUNIT_TEST_SUITE_REGISTRATION(AdvisoryAdvisoryPackageTest);

//This allows running only this single test suite, by using `getRegistry("AdvisoryAdvisoryTest_suite")` in run_tests.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(AdvisoryAdvisoryPackageTest, "AdvisoryAdvisoryPackageTest_suite");

void AdvisoryAdvisoryPackageTest::setUp() {
    RepoFixture::setUp();
    RepoFixture::add_repo_repomd("repomd-repo1");
    base->get_rpm_advisory_sack().load_advisories_from_solvsack();
    //TODO(amatej): get this by id because later someone could add another SECURITY updateinfo
    auto advisory = base->get_rpm_advisory_sack().new_query().ifilter_type(libdnf::sack::QueryCmp::EQ, libdnf::Advisory::Type::SECURITY).list().begin()->get();
    std::vector<libdnf::AdvisoryCollection> collections = advisory->get_collections();
    collections[0].get_packages(packages);
}

void AdvisoryAdvisoryPackageTest::test_get_name() {
    // Tests get_name method
    CPPUNIT_ASSERT_EQUAL(std::string("pkg"), std::string(packages[0].get_name()));
}

void AdvisoryAdvisoryPackageTest::test_get_version() {
    // Tests get_version method
    CPPUNIT_ASSERT_EQUAL(std::string("1.2"), std::string(packages[0].get_version()));
}

void AdvisoryAdvisoryPackageTest::test_get_evr() {
    // Tests get_evr method
    CPPUNIT_ASSERT_EQUAL(std::string("1.2-3"), std::string(packages[0].get_evr()));
}

void AdvisoryAdvisoryPackageTest::test_get_arch() {
    // Tests get_arch method
    CPPUNIT_ASSERT_EQUAL(std::string("x86_64"), std::string(packages[0].get_arch()));
}
