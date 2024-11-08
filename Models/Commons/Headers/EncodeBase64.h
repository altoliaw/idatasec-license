#pragma once
/** @file EncodeBase64.h
 *
 * The base64 class
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "EncodePrototype.h"

typedef struct EncodeBase64 EncodeBase64;

struct EncodeBase64 {
	// The object from the prototype
	EncodePrototype parent;
};

// EncodeBase64 constructor
void EncodeBase64_Construct(EncodeBase64*);
// EncodeBase64 destructor
void EncodeBase64_Destruct(EncodeBase64*);