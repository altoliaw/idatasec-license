#include "../Headers/Test_EncodeBase64.h"

/**
 * Main process for the model unit test
 */
int main() {
    int isFault = 0;
    isFault |= cmocka_run_group_tests(Test_EncodeBase64_Group, NULL, NULL);
    return isFault;
}

/**
 * base64EncodeProcess test
 */
void Test_EncodeBase64_base64EncodeProcess(void** State) {
	EncodeBase64 instance;
	EncodeBase64_Construct(&instance);

	const unsigned char testData[] = "Hello, World!";
    size_t encodedLen, decodedLen;
    
    // Demonstrating the encoding process
	unsigned char* encoded = NULL;
	unsigned char* decoded = NULL;
    instance.parent.encodeString(testData, (const unsigned long)strlen((char*)testData), &encoded, &encodedLen);
    
    // // Verifying the decoding process
    instance.parent.decodeString((const unsigned char*)encoded, (const unsigned long)encodedLen, &decoded, &decodedLen);
    
    // Releasing the allocated resources
	if(encoded != NULL) {
    	free(encoded);
	}
	if(decoded != NULL) {
    	free(decoded);
	}

	EncodeBase64_Destruct(&instance);
}