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


#include "test_advisory_query.hpp"

#include "libdnf/rpm/package_set.hpp"
#include "libdnf/rpm/solv_query.hpp"

#include <filesystem>
#include <set>
#include <vector>


CPPUNIT_TEST_SUITE_REGISTRATION(AdvisoryAdvisoryQueryTest);

//This allows running only this single test suite, by using `getRegistry("AdvisoryAdvisoryQueryTest_suite")` in run_tests.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(AdvisoryAdvisoryQueryTest, "AdvisoryAdvisoryQueryTest_suite");

void AdvisoryAdvisoryQueryTest::setUp() {
    RepoFixture::setUp();
    RepoFixture::add_repo_repomd("repomd-repo1");
    advisory_sack = &(base->get_rpm_advisory_sack());
    advisory_sack->load_advisories_from_solvsack();
}

void AdvisoryAdvisoryQueryTest::test_size() {
    libdnf::AdvisoryQuery query = advisory_sack->new_query();
    //TODO(amatej): Add tests for actual content
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_id() {
    // Tests ifilter_id method
    std::set<libdnf::WeakPtr<libdnf::Advisory, false>> adv_set = advisory_sack->new_query().get_data();
    std::set<libdnf::WeakPtr<libdnf::Advisory, false>>::iterator adv_iter = adv_set.begin();
    int id1 = adv_iter->get()->get_id().id;
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_id(libdnf::sack::QueryCmp::EQ, id1);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    std::advance(adv_iter, 1);
    int id2 = adv_iter->get()->get_id().id;
    query = advisory_sack->new_query().ifilter_id(libdnf::sack::QueryCmp::EQ, std::vector<std::int64_t>{id1, id2});
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_name() {
    // Tests ifilter_name method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_name(libdnf::sack::QueryCmp::GLOB, "*2020-1");
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_name(libdnf::sack::QueryCmp::EQ, std::vector<std::string>{"DNF-2019-1", "DNF-2020-1"});
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_type() {
    // Tests ifilter_type method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_type(libdnf::sack::QueryCmp::EQ, libdnf::Advisory::Type::BUGFIX);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_type(libdnf::sack::QueryCmp::EQ, libdnf::Advisory::Type::ENHANCEMENT);
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());

    query = advisory_sack->new_query().ifilter_type(libdnf::sack::QueryCmp::EQ, std::vector<libdnf::Advisory::Type>{libdnf::Advisory::Type::BUGFIX, libdnf::Advisory::Type::SECURITY});
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_package() {
    // Tests ifilter_package method
    libdnf::rpm::SolvQuery pkg_query(sack);
    pkg_query.ifilter_nevra(libdnf::sack::QueryCmp::EQ, {"pkg-1.2-3.x86_64"});
    CPPUNIT_ASSERT_EQUAL_MESSAGE( "No package or more than one package found.", 1lu, pkg_query.size());

    libdnf::rpm::Package package = *(pkg_query.begin());

    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_package(libdnf::sack::QueryCmp::EQ, package);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());
    CPPUNIT_ASSERT_EQUAL(std::string("DNF-2019-1"), std::string(query.get()->get_name()));

    query = advisory_sack->new_query().ifilter_package(libdnf::sack::QueryCmp::GTE, package);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());
    CPPUNIT_ASSERT_EQUAL(std::string("DNF-2019-1"), std::string(query.get()->get_name()));

    query = advisory_sack->new_query().ifilter_package(libdnf::sack::QueryCmp::LTE, package);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());
    CPPUNIT_ASSERT_EQUAL(std::string("DNF-2019-1"), std::string(query.get()->get_name()));

    query = advisory_sack->new_query().ifilter_package(libdnf::sack::QueryCmp::GT, package);
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());

    query = advisory_sack->new_query().ifilter_package(libdnf::sack::QueryCmp::LT, package);
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_package_set() {
    // Tests ifilter_package_set method
    libdnf::rpm::SolvQuery pkg_query(sack);

    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_package_set(libdnf::sack::QueryCmp::EQ, pkg_query);
    CPPUNIT_ASSERT_EQUAL(std::string("DNF-2019-1"), std::string(query.get()->get_name()));
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_package_set(libdnf::sack::QueryCmp::GTE, pkg_query);
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());
    CPPUNIT_ASSERT_EQUAL(std::string("DNF-2019-1"), std::string(query.get()->get_name()));

    //TODO(amatej): I am gonna need way more packages for this (rather way more advisories.. I should test >,>=,==,<=,<)
}

void AdvisoryAdvisoryQueryTest::test_ifilter_cve() {
    // Tests ifilter_cve method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_CVE(libdnf::sack::QueryCmp::EQ, "3333");
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_CVE(libdnf::sack::QueryCmp::EQ, std::vector<std::string>{"1111", "3333"});
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());

    query = advisory_sack->new_query().ifilter_CVE(libdnf::sack::QueryCmp::EQ, std::vector<std::string>{"1111", "4444"});
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_CVE(libdnf::sack::QueryCmp::GLOB, "*");
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_bug() {
    // Tests ifilter_bug method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_bug(libdnf::sack::QueryCmp::EQ, "2222");
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_bug(libdnf::sack::QueryCmp::EQ, std::vector<std::string>{"1111", "3333"});
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());

    query = advisory_sack->new_query().ifilter_bug(libdnf::sack::QueryCmp::GLOB, "*");
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_severity() {
    // Tests ifilter_severity method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_severity(libdnf::sack::QueryCmp::EQ, "moderate");
    CPPUNIT_ASSERT_EQUAL(1lu, query.size());

    query = advisory_sack->new_query().ifilter_severity(libdnf::sack::QueryCmp::EQ, std::vector<std::string>{"moderate", "critical"});
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());

    query = advisory_sack->new_query().ifilter_severity(libdnf::sack::QueryCmp::GLOB, "*");
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());
}

void AdvisoryAdvisoryQueryTest::test_ifilter_applicable() {
    // Tests ifilter_applicable method
    libdnf::AdvisoryQuery query = advisory_sack->new_query().ifilter_applicable(true);
    CPPUNIT_ASSERT_EQUAL(2lu, query.size());

    query = query.ifilter_applicable(false);
    CPPUNIT_ASSERT_EQUAL(0lu, query.size());

    //TODO(amatej): I should have atleas one not applicable
    libdnf::AdvisoryQuery query_not_applicable = advisory_sack->new_query().ifilter_applicable(false);
    CPPUNIT_ASSERT_EQUAL(0lu, query_not_applicable.size());

}

void AdvisoryAdvisoryQueryTest::test_get_advisory_packages() {
    // Tests get_advisory_packages method
    std::vector<libdnf::AdvisoryPackage> adv_pkgs = advisory_sack->new_query().get_advisory_packages();
    CPPUNIT_ASSERT_EQUAL(5lu, adv_pkgs.size());

    CPPUNIT_ASSERT_EQUAL(std::string("pkg"), adv_pkgs[0].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("1.2-3"), adv_pkgs[0].get_evr());

    CPPUNIT_ASSERT_EQUAL(std::string("bitcoin"), adv_pkgs[1].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("2.5-1"), adv_pkgs[1].get_evr());

    CPPUNIT_ASSERT_EQUAL(std::string("filesystem"), adv_pkgs[2].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("3.9-2.fc29"), adv_pkgs[2].get_evr());

    CPPUNIT_ASSERT_EQUAL(std::string("wget"), adv_pkgs[3].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("1.19.5-5.fc29"), adv_pkgs[3].get_evr());

    CPPUNIT_ASSERT_EQUAL(std::string("yum"), adv_pkgs[4].get_name());
    CPPUNIT_ASSERT_EQUAL(std::string("3.4.3-0"), adv_pkgs[4].get_evr());
}
