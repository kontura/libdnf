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


#include "test_advisory.hpp"

#include "libdnf/rpm/package_set.hpp"
#include "libdnf/rpm/solv_query.hpp"

#include <filesystem>
#include <set>
#include <vector>


CPPUNIT_TEST_SUITE_REGISTRATION(AdvisoryAdvisoryTest);

//This allows running only this single test suite, by using `getRegistry("AdvisoryAdvisoryTest_suite")` in run_tests.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(AdvisoryAdvisoryTest, "AdvisoryAdvisoryTest_suite");

void AdvisoryAdvisoryTest::setUp() {
    RepoFixture::setUp();
    RepoFixture::add_repo_repomd("repomd-repo1");
    advisory_sack = &(base->get_rpm_advisory_sack());
    advisory_sack->load_advisories_from_solvsack();
    advisory = advisory_sack->new_query().ifilter_type(libdnf::sack::QueryCmp::EQ, libdnf::Advisory::Type::SECURITY).list().begin()->get();
}

void AdvisoryAdvisoryTest::test_get_name() {
    // Tests get_name method
    CPPUNIT_ASSERT_EQUAL(std::string(advisory->get_name()), std::string("DNF-2019-1"));
}

void AdvisoryAdvisoryTest::test_get_type() {
    // Tests get_type method
    CPPUNIT_ASSERT_EQUAL(advisory->get_type(), libdnf::Advisory::Type::SECURITY);
}

void AdvisoryAdvisoryTest::test_get_severity() {
    // Tests get_severity method
    CPPUNIT_ASSERT_EQUAL(std::string(std::string("moderate")), std::string(advisory->get_severity()));
}

void AdvisoryAdvisoryTest::test_get_references() {
    // Tests get_references method
    std::vector<libdnf::AdvisoryReference> refs = advisory->get_references();
    CPPUNIT_ASSERT_EQUAL(1lu, refs.size());

    libdnf::AdvisoryReference r = refs[0];
    CPPUNIT_ASSERT_EQUAL(std::string("1111"), r.get_id());
    CPPUNIT_ASSERT_EQUAL(libdnf::AdvisoryReference::Type::CVE, r.get_type());
    CPPUNIT_ASSERT_EQUAL(std::string("CVE-2999"), r.get_title());
    CPPUNIT_ASSERT_EQUAL(std::string("https://foobar/foobarupdate_2"), r.get_url());
}

void AdvisoryAdvisoryTest::test_get_collections() {
    // Tests get_collections method
    std::vector<libdnf::AdvisoryCollection> colls = advisory->get_collections();
    CPPUNIT_ASSERT_EQUAL(1lu, colls.size());

    libdnf::AdvisoryCollection c = colls[0];
    std::vector<libdnf::AdvisoryPackage> pkgs = c.get_packages();
    CPPUNIT_ASSERT_EQUAL(2lu, pkgs.size());
    CPPUNIT_ASSERT_EQUAL(std::string("pkg"), pkgs[0].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("filesystem"), pkgs[1].get_name());

    std::vector<libdnf::AdvisoryModule> mods = c.get_modules();
    CPPUNIT_ASSERT_EQUAL(2lu, mods.size());
    CPPUNIT_ASSERT_EQUAL(std::string("perl-DBI"), mods[0].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("ethereum"), mods[1].get_name());

    libdnf::Advisory * advisory2 = advisory_sack->new_query().ifilter_name(libdnf::sack::QueryCmp::EQ, "DNF-2020-1").list().begin()->get();
    colls = advisory2->get_collections();
    CPPUNIT_ASSERT_EQUAL(2lu, colls.size());

    libdnf::AdvisoryCollection c1 = colls[0];
    pkgs = c1.get_packages();
    CPPUNIT_ASSERT_EQUAL(2lu, pkgs.size());
    CPPUNIT_ASSERT_EQUAL(std::string("wget"), pkgs[0].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("yum"), pkgs[1].get_name());

    mods = c1.get_modules();
    CPPUNIT_ASSERT_EQUAL(1lu, mods.size());
    CPPUNIT_ASSERT_EQUAL(std::string("perl-DBI"), mods[0].get_name());

    libdnf::AdvisoryCollection c2 = colls[1];
    pkgs = c2.get_packages();
    CPPUNIT_ASSERT_EQUAL(1lu, pkgs.size());
    CPPUNIT_ASSERT_EQUAL(std::string("bitcoin"), pkgs[0].get_name());

    mods = c2.get_modules();
    CPPUNIT_ASSERT_EQUAL(1lu, mods.size());
    CPPUNIT_ASSERT_EQUAL(std::string("perl"), mods[0].get_name());
}

