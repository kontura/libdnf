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


#ifndef TEST_LIBDNF_ADVISORY_ADVISORY_PACKAGE_HPP
#define TEST_LIBDNF_ADVISORY_ADVISORY_PACKAGE_HPP


#include "../rpm/repo_fixture.hpp"

#include <cppunit/extensions/HelperMacros.h>

#include "libdnf/advisory/advisory_package.hpp"
#include "libdnf/advisory/advisory_collection.hpp"

class AdvisoryAdvisoryPackageTest : public RepoFixture {
    CPPUNIT_TEST_SUITE(AdvisoryAdvisoryPackageTest);

    CPPUNIT_TEST(test_get_name);
    CPPUNIT_TEST(test_get_version);
    CPPUNIT_TEST(test_get_evr);
    CPPUNIT_TEST(test_get_arch);

    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

    void test_get_name();
    void test_get_version();
    void test_get_evr();
    void test_get_arch();

private:
    std::vector<libdnf::AdvisoryPackage> packages;
};


#endif  // TEST_LIBDNF_ADVISORY_ADVISORY_PACKAGE_HPP
