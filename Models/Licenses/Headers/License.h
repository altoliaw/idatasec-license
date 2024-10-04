#pragma once
/** @file License.h
 * The license class definition; the license format is modelled as the UUID (version 4);
 * The length of the UUID is 36 and the string format is modelled as "8-4-4-4-12" bytes.
 *
 * @author Nick, Liao
 * @date 2024/09/27
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// The two included files are compiled from the official project and made from the 
// the vendors, please refer to the .json file, namely, globalDependencies.json.
#include "../../../Vendors/libGcrypt/Includes/gcrypt.h"  // The gcrypt (gcrypt.h) from the third parties
#include "../../../Vendors/libUtil-Linux/Includes/uuid/uuid.h" // For generating the UUID

#define AES_KEY_SIZE 32 // 32 bytes for AES-256
#define BLOCK_SIZE 16   // AES block size

typedef struct License License;

/**
 * License class definition
 */
struct License {

	// The key for encryption
	unsigned char encryptedKey[37];

	// Function pointer, referring to the function, namely generateLicenseIntermediateKey
	void (*generateLicenseIntermediateKey)(License*, unsigned char*, const unsigned char*, unsigned int);
	// Function pointer, referring to the function, namely generateLicenseKey
	void (*generateLicenseKey)(License*, unsigned char*, const unsigned char*, unsigned int);

};

// License constructor
void License_Constrcut(License*);
// License destructor
void License_Destrcut(License*);