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


#ifndef TEST_LIBDNF_ADVISORY_ADVISORY_HPP
#define TEST_LIBDNF_ADVISORY_ADVISORY_HPP


#include "../rpm/repo_fixture.hpp"

#include <cppunit/extensions/HelperMacros.h>

#include "libdnf/advisory/advisory_sack.hpp"
#include "libdnf/advisory/advisory_collection.hpp"

class AdvisoryAdvisoryTest : public RepoFixture {
    CPPUNIT_TEST_SUITE(AdvisoryAdvisoryTest);

    CPPUNIT_TEST(test_get_name);
    CPPUNIT_TEST(test_get_type);
    CPPUNIT_TEST(test_get_severity);
    CPPUNIT_TEST(test_get_references);
    CPPUNIT_TEST(test_get_collections);

    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

    void test_get_name();
    void test_get_type();
    void test_get_severity();
    //void test_ifilter_package();

    void test_get_references();
    void test_get_collections();
private:
    libdnf::AdvisorySack * advisory_sack;
    libdnf::Advisory * advisory;
};


#endif  // TEST_LIBDNF_ADVISORY_ADVISORY_HPP
