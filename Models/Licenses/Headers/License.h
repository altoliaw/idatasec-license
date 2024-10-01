#pragma once
/** @file License.h
 * The license class definition; the license format is modelled as the UUID (version 4);
 * The length of the UUID is 36 and the string format is modelled as "8-4-4-4-12" bytes.
 *
 * @author Nick, Liao
 * @date 2024/09/27
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../Vendors/libGcrypt/Includes/gcrypt.h"  // The gcrypt (gcrypt.h) from the third parties
#include "../../Vendors/libUtil-Linux/Includes/uuid/uuid.h"

typedef struct License License;

struct License {
};