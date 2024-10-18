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

#define LICENSE_CONTENT_MESSAGE_VARIABLE1 "Authorized Entity:"
#define LICENSE_CONTENT_MESSAGE_VARIABLE2 "Authorized Deadline:"
#define LICENSE_CONTENT_MESSAGE_VARIABLE3 "Authorized Time:"
#define LICENSE_CONTENT_MESSAGE LICENSE_CONTENT_MESSAGE_VARIABLE1 "%.*s\n" \
            LICENSE_CONTENT_MESSAGE_VARIABLE2 "%lu\n" \
            LICENSE_CONTENT_MESSAGE_VARIABLE3 "%lu\n"


/**
 * For common values's definition in the "License" class
 */
enum LicenseConstants {
    LICENSE_MAC_ADDRESS = 12,        // The number of the MAC address
    LICENSE_BLOCK_SIZE = 16,         // AES block size and IV size
    LICENSE_AES_KEY_SIZE = 32,       // 32 bytes for AES-256
    LICENSE_LICENSE_KEY_LENGTH = 64, // License key length
    LICENSE_LICENSE_CONTENTS_LENGTH = 1024 // License contents length
};

typedef struct License License;

/**
 * License class definition
 */
struct License {
    // For reserving the license layout value with the specified field order; the field order is defined
    // in the variable, "globalLicenseFields", in the License.c; the pointer shall be allocated/deallocated 
    // with the dynamic memory allocation/deallocation
    unsigned char** valueForGlobalLicenseFields;
    // The length for the array above
    unsigned short valueForGlobalLicenseFieldsLength;
    // The AES secret key
    unsigned char secretKey[LICENSE_AES_KEY_SIZE];
    // The iv value for AES; the size is equal to 2 * LICENSE_BLOCK_SIZE
    unsigned char iv[LICENSE_AES_KEY_SIZE];
    // Reserving the mac address in the hex format
    unsigned char macAddress[LICENSE_MAC_ADDRESS];
    // The license key
    unsigned char licenseKey[LICENSE_LICENSE_KEY_LENGTH];
    // License contents storage
    unsigned char licenseContents[LICENSE_LICENSE_CONTENTS_LENGTH];

    // Function pointer, referring to the function, namely generateAES256Key
    char (*generateAES256Key)(License*, const unsigned char*, const unsigned char*);
    // Function pointer, referring to the function, namely generateLicense
    char (*generateLicense)(License*, const unsigned char*, const unsigned char*, const unsigned char*, const unsigned char*);
    // Function pointer, referring to the function, namely validateLicense
    char (*validateLicense)(License*, const unsigned char*, const unsigned char*, const unsigned char*);
};

// License constructor
void License_Constrcut(License*);
// License destructor
void License_Destrcut(License*);