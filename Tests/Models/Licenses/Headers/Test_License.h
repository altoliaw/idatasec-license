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


#include "../../../Models/Licenses/Headers/License.h"


void Test_License_generateAES256KeyProcess(void**);
void Test_License_generateClientInformationProcess(void**);
void Test_License_generateAsymmetricKeyValuePairProcess(void**);
void Test_License_generateLicenseProcess(void**);
void Test_License_validateLicenseProcess(void**);

const struct CMUnitTest Test_License_Group[] = {
    cmocka_unit_test(Test_License_generateAES256KeyProcess),
    cmocka_unit_test(Test_License_generateClientInformationProcess),
    cmocka_unit_test(Test_License_generateAsymmetricKeyValuePairProcess),
    cmocka_unit_test(Test_License_generateLicenseProcess),
    cmocka_unit_test(Test_License_validateLicenseProcess),
};
