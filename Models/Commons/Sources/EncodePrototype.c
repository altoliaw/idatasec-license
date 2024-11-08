/**
 * @see License.h
 */
#include "../Headers/EncodePrototype.h"

/**
 * Constructor
 * 
 * @param instance [EncodePrototype*] The instance of the EncodePrototype
 */
void EncodePrototype_Construct(EncodePrototype* instance, const unsigned char* className) {
	(instance->className)[0] = '\0';
	strcpy((char*)(instance->className), (const char*)className);
	instance->encodeString= NULL;
	instance->decodeString= NULL;
}

/**
 * Destructor
 * 
 * @param instance [EncodePrototype*] The instance of the EncodePrototype
 */
void EncodePrototype_Destruct(EncodePrototype* instance) {
	(instance->className)[0] = '\0';
	instance->encodeString= NULL;
	instance->decodeString= NULL;
}