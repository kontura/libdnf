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


#ifndef TEST_LIBDNF_ADVISORY_ADVISORY_QUERY_HPP
#define TEST_LIBDNF_ADVISORY_ADVISORY_QUERY_HPP


#include "../rpm/repo_fixture.hpp"

#include <cppunit/extensions/HelperMacros.h>

#include "libdnf/advisory/advisory_sack.hpp"

class AdvisoryAdvisoryQueryTest : public RepoFixture {
    CPPUNIT_TEST_SUITE(AdvisoryAdvisoryQueryTest);

    CPPUNIT_TEST(test_size);
    CPPUNIT_TEST(test_ifilter_id);
    CPPUNIT_TEST(test_ifilter_name);
    CPPUNIT_TEST(test_ifilter_type);
    CPPUNIT_TEST(test_ifilter_package);
    CPPUNIT_TEST(test_ifilter_package_set);
    CPPUNIT_TEST(test_ifilter_cve);
    CPPUNIT_TEST(test_ifilter_bug);
    CPPUNIT_TEST(test_ifilter_severity);
    CPPUNIT_TEST(test_ifilter_applicable);
    CPPUNIT_TEST(test_get_advisory_packages);

    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

    void test_size();
    void test_ifilter_id();
    void test_ifilter_name();
    void test_ifilter_type();
    void test_ifilter_package();
    void test_ifilter_package_set();
    void test_ifilter_cve();
    void test_ifilter_bug();
    void test_ifilter_severity();
    void test_ifilter_applicable();
    void test_get_advisory_packages();
private:
    libdnf::AdvisorySack * advisory_sack;
};


#endif  // TEST_LIBDNF_ADVISORY_ADVISORY_QUERY_HPP
