#include "../Headers/Test_License.h"

/**
 * Main process for the model unit test
 */
int main() {
	int isFault = 0;
	isFault |= cmocka_run_group_tests(Test_License_Group, NULL, NULL);
	return isFault;
}


/**
 * GenerateLicenseKeyProcess test
 */
void Test_License_generateLicenseKeyProcess(void** State) {
	License instance;
	License_Constrcut(&instance);
	unsigned char licenseKey[37];  // 36 bytes + 1 byte (stop character) UUID v4 string
	instance.generateLicenseKey(&instance, licenseKey, "thisisthe32byteaesencryptionkey!", 365);
	
	License_Destrcut(&instance);

}