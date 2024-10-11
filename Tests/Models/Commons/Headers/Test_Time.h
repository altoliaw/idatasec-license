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

#include "../../../Models/Commons/Headers/Time.h"

void Test_Time_getEpochProcess(void**);
void Test_Time_getStringToEpoch(void**);
void Test_Time_getEpochToString(void**);

const struct CMUnitTest Test_Time_Group[] = {
    cmocka_unit_test(Test_Time_getEpochProcess),
    cmocka_unit_test(Test_Time_getStringToEpoch),
    cmocka_unit_test(Test_Time_getEpochToString),
};
