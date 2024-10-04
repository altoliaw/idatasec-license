#pragma once
/** @file Test_License.h
 * Unit test for Base64 encoding and decoding
 *
 * @author Nick Liao
 * @date 2024/10/04
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>


#include "../../../Models/Licenses/Headers/License.h"

void Test_License_generateLicenseKeyProcess(void**);

const struct CMUnitTest Test_License_Group[] = {
    cmocka_unit_test(Test_License_generateLicenseKeyProcess),
};
