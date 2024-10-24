/**
 * @see LicenseMainCaller.h
 */
#include "../Headers/LicenseGenerationController/LicenseMainCaller.h"
static void argumentAssignment(int, char**, unsigned char**, unsigned char**, unsigned char**, unsigned char**, unsigned char**, unsigned int*);

/**
 * The starting entry of the license generation process
 *
 * @param argc [int] The number of arguments
 * @param argv [char**] The arguments; the index 0 is the executable name and the meaning of the others' indexes are displayed as below:
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
char start(int argc, char** argv) {
    char isSuccess = 0x0;
    // The definition of the default argument count
#define DEFAULT_ARGUMENT_COUNT 7
    if (argc < DEFAULT_ARGUMENT_COUNT) {
        return isSuccess = 0x1;
    }
    // Removing the default argument count
#undef DEFAULT_ARGUMENT_COUNT

// The extension of the license key pair (private key)
#define DEFAULT_LICENSE_KEY_PAIR_PRIVATE_EXTENSION ".pem"
// The extension of the license key pair (public key)
#define DEFAULT_LICENSE_KEY_PAIR_PUBLIC_EXTENSION ".pub"

    // The variables and variables' assignments
    unsigned char* aes256KeyPath = NULL;
    unsigned char* interfaceName = NULL;
    unsigned char* baseNameLicenseKeyPairPath = NULL;
    unsigned char* informationPath = NULL;
    unsigned char* licensePath = NULL;
    unsigned int days = 0;
    argumentAssignment(argc, argv, &aes256KeyPath, &interfaceName, &baseNameLicenseKeyPairPath, &informationPath, &licensePath, &days);

    // Initializing the "License" instance
    License instance;
    License_Construct(&instance);
    // Generating the AES-256 key for encrypting the plaintext information; if the file exists, the key will be regenerated
    isSuccess |= (isSuccess == 0x0) ? instance.generateAES256Key(&instance, (const unsigned char*)interfaceName, (const unsigned char*)aes256KeyPath) : 0x1;

    // Generating the license key pair; if the file exists, the phase will be ignored
    instance.generateAsymmetricKeyValuePair(&instance, (const unsigned char*)baseNameLicenseKeyPairPath);

    // Generating the license
    unsigned char* licensePrivateKeyPath = NULL;
	unsigned int pathLength = (unsigned int)strlen((const char*)baseNameLicenseKeyPairPath);
	unsigned int extensionLength = (unsigned int)strlen((const char*)DEFAULT_LICENSE_KEY_PAIR_PRIVATE_EXTENSION);
	licensePrivateKeyPath = calloc(pathLength + extensionLength + 1, sizeof(unsigned char));
	// Generating the license private key path
	memcpy(licensePrivateKeyPath, baseNameLicenseKeyPairPath, pathLength);
	memcpy(licensePrivateKeyPath + pathLength, DEFAULT_LICENSE_KEY_PAIR_PRIVATE_EXTENSION, extensionLength);
	licensePrivateKeyPath[pathLength + extensionLength] = '\0';
	// Generating the license
    instance.generateLicense(&instance, interfaceName, informationPath, aes256KeyPath, licensePrivateKeyPath, licensePath, days);

    // Destructing the "License" instance
    License_Destruct(&instance);

// Removing the extension of the license key pair (private key)
#undef DEFAULT_LICENSE_KEY_PAIR_PRIVATE_EXTENSION
// Removing the extension of the license key pair (public key)
#undef DEFAULT_LICENSE_KEY_PAIR_PUBLIC_EXTENSION

    return isSuccess;
}

/**
 * Assigning the arguments from the input arguments
 *
 * @param argc [int] The number of arguments
 * @param argv [char**] The contents for all arguments
 * @param aes256KeyPath [unsigned char**] The AES-256 key path
 * @param interfaceName [unsigned char**] The interface name for registering NIC
 * @param baseNameLicenseKeyPairPath [unsigned char**] The base name for the license key pair
 * @param informationPath [unsigned char**] The information path of the client
 * @param licensePath [unsigned char**] The license path for generating the license
 * @param days [unsigned int*] The days for the license expiration
 */
static void argumentAssignment(int argc, char** argv,
                               unsigned char** aes256KeyPath,
                               unsigned char** interfaceName,
                               unsigned char** baseNameLicenseKeyPairPath,
                               unsigned char** informationPath,
                               unsigned char** licensePath,
                               unsigned int* days) {
    unsigned int i = 0;
    // Assigning the arguments
    for (i = 1; i < argc; i++) {
        switch (i) {
            case 1:
                *aes256KeyPath = argv[i];
                break;
            case 2:
                *baseNameLicenseKeyPairPath = argv[i];
                break;
            case 3:
                *interfaceName = argv[i];
                break;
            case 4:
                *informationPath = argv[i];
                break;
            case 5:
                *licensePath = argv[i];
                break;
            case 6:
                *days = atoi(argv[i]);
                break;
        }
    }
}