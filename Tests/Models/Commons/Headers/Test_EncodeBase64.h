#pragma once
/** @file Test_EncodeBase64.h
 
 *
 * @author Nick Liao
 * @date 2024/10/04
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../../../Models/Commons/Headers/EncodeBase64.h"

void Test_EncodeBase64_base64EncodeProcess(void**);


const struct CMUnitTest Test_EncodeBase64_Group[] = {
    cmocka_unit_test(Test_EncodeBase64_base64EncodeProcess),
};
