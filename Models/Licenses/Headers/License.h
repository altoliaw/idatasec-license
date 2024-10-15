#pragma once
/** @file License.h
 * The license class definition using AES CBC + PKCS#7
 *
 * @author Nick, Liao
 * @date 2024/09/27
 * 
 * @remark The dependencies are "Commons.Time".
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

// For obtaining the network information, such as MAC
#ifndef __USE_MISC  // For ensuring the unistd.h can be included completely
	#define __USE_MISC
#endif
#include <net/if.h>
#include <stdint.h>  // For ensuring the unistd.h can be compiled accurately
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// The dependencies files in the project
#include "../../Commons/Headers/Time.h"

// The two included files are compiled from the official project and made from the
// the vendors, please refer to the .json file, namely, globalDependencies.json.
#include "../../../Vendors/libGcrypt/Includes/gcrypt.h"         // The gcrypt (gcrypt.h) from the third parties
#include "../../../Vendors/libUtil-Linux/Includes/uuid/uuid.h"  // For generating the UUID

/**
 * For common values's definition in the "License" class
 */
enum LicenseConstants {
    LICENSE_MAC_ADDRESS = 12,        // The number of the MAC address
    LICENSE_BLOCK_SIZE = 16,         // AES block size
    LICENSE_AES_KEY_SIZE = 32,       // 32 bytes for AES-256
    LICENSE_LICENSE_KEY_LENGTH = 64  // License key length
};

typedef struct License License;

/**
 * License class definition
 */
struct License {
    // The AES secret key
    unsigned char secretKey[LICENSE_AES_KEY_SIZE];
    unsigned char macAddress[LICENSE_MAC_ADDRESS];
    unsigned char licenseKeyLength[LICENSE_LICENSE_KEY_LENGTH];

    // Function pointer, referring to the function, namely generateAES256Key
    char (*generateAES256Key)(License*, const unsigned char*, const unsigned char*);

    // Function pointer, referring to the function, namely generateLicenseKey
    char (*generateLicenseKey)(License*, const unsigned char*, const unsigned char*, const unsigned char*);

    // Function pointer, referring to the function, namely generateLicenseIntermediateKey
    void (*generateLicenseIntermediateKey)(License*, unsigned char*, const unsigned char*, unsigned int);
};

// License constructor
void License_Constrcut(License*);
// License destructor
void License_Destrcut(License*);