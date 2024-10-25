#pragma once
/** @file Test_License.h
 
 *
 * @author Nick Liao
 * @date 2024/10/04
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// The file library
#include <string.h>

#include "../../../Headers/LicenseGenerationController/LicenseMainCaller.h"


void Test_LicenseMainCaller_startProcess(void**);

const struct CMUnitTest Test_License_Group[] = {
    cmocka_unit_test(Test_LicenseMainCaller_startProcess),
};
