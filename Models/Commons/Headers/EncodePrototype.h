#pragma once
/** @file EncodePrototype.h
 * 
 * The encoded prototype class
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct EncodePrototype EncodePrototype;

/**
 * The prototype of the encoded class
 */
struct EncodePrototype {
	// Reserving the class name
	unsigned char className [1024];
	// Encoding string
	char (*encodeString)(const unsigned char*, const unsigned long, unsigned char**, unsigned long*);
	// Decoding string
	char (*decodeString)(const unsigned char*, const unsigned long, unsigned char**, unsigned long*);
};

// EncodePrototype constructor
void EncodePrototype_Construct(EncodePrototype*, const unsigned char*);
// EncodePrototype destructor
void EncodePrototype_Destruct(EncodePrototype*);