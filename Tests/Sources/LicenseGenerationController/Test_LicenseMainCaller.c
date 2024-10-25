#include "../../Headers/LicenseGenerationController/Test_LicenseGenerationController.h"

static void removeFiles(int, char**);

/**
 * Main process for the model unit test
 */
int main() {
    int isFault = 0;
    isFault |= cmocka_run_group_tests(Test_License_Group, NULL, NULL);
    return isFault;
}

/**
 * generateAES256KeyProcess test
 *
 * index 1: The key location for encrypting plaintext information; the key belongs to the AES-256 key
 * index 2: The registered interface name for NIC (e.g., ens192)
 * index 3: The license key base name (../../xxx); two keys (private key and public key) are generated for the license and the two key names are depended on this base name
 * index 4: The information file location from the client
 * index 5: The license file path; the path shall contain the license file name and the extension
 * index 6: The days for the license expiration (e.g., 365)
 *
 * @note The example are shown as below:
 * unsigned char* aes256KeyPath = "../../../../Outputs/aes256Key.aes";
 * unsigned char* interfaceName = "ens192";
 * unsigned char* baseNameLicenseKeyPairPath = "../../../../Outputs/license.key";
 * unsigned char* informationPath = "../../../../Outputs/content.info";
 * // unsigned char* licensePrivateKeyPath = "../../../../Outputs/license.key.pem";
 * unsigned char* licensePath = "../../../../Outputs/license.lic";
 */
void Test_LicenseMainCaller_startProcess(void** State) {
    // Deleting the existing files

    char* argv[] = {"./LicenseMainCaller",
                    "../../../Outputs/aes256Key.aes",
                    "ens192",
                    "../../../Outputs/license.key",
                    "../../../Outputs/content.info",
                    "../../../Outputs/license.lic",
                    "365",
                    NULL};

    unsigned int i = 0;
    for (; argv[i] != NULL; i++) {  // Looping until the last element when the element is NULL
    }
    int argc = i;  // The index of the last element is equal to the number of the arguments
    // Removing the file in advance
    removeFiles(argc, argv);
	// Generating the license
	start(argc, argv);
    // assert_int_equal(start(argc, argv), 0);
}

/**
 * Removing the files
 *
 * @param number [int] The number of the array below
 * @param array [char**] The array of the file paths
 */
static void removeFiles(int number, char** array) {
    for (unsigned char i = 1; i < number - 1; i++) {  // The first element is the executable name and the last second element is the days
        unsigned int loopNumber = 1;
        // Skipping the information file and the AES key file (because the client file depends on the AES key file)
        if (i == 1| i == 4) {
            continue;
        } else if (i == 3) {  // This path is the license key pair base path
            loopNumber = 2;
        }

        size_t pathLength = strlen(array[i]);
        for (unsigned char j = 0; j < loopNumber; j++) {
            char path[1024] = {'\0'};
            strcpy(path, array[i]);  // Copying the content including '\0'
			// When i == 3, the license key pair is generated.
            if (i == 3) {
				if (j == 0) {
					strcat(path, ".pem");
				} else {
					strcat(path, ".pub");
				}
            }

			// Removing the files by verifying the file existence
            FILE* fileDescriptor = fopen(path, "rb");
            if (fileDescriptor != NULL) {
                fclose(fileDescriptor);
                fileDescriptor = NULL;
                remove(path);
            }
        }
    }
}