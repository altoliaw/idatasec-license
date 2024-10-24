#include "../Headers/Test_License.h"

static char getMacAddress(const unsigned char*, unsigned char*, const unsigned int);

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
 */
void Test_License_generateAES256KeyProcess(void** State) {
	// For reserving the length for the MAC and the storage itself
    enum { macAddressLength = 6 };

	License instance;
	License_Construct(&instance);
	const unsigned char* interfaceName = "ens192";
	const unsigned char* path = "../../../../Outputs/aes256Key.aes";
	instance.generateAES256Key(&instance, interfaceName, path);

	// Calling for the MAC information
	unsigned char macAddress[macAddressLength] = {'\0'};
	getMacAddress(interfaceName, macAddress, (const unsigned int) macAddressLength);
	unsigned char macAddressInHex[LICENSE_MAC_ADDRESS] = {'\0'};

	int cumulativeLength = 0;
	for (unsigned int i= 0; i< macAddressLength; i++ ) {
		cumulativeLength += sprintf(macAddressInHex + cumulativeLength, "%02x", macAddress[i]);
	}

	// Comparing with the characters
	for (unsigned int i= 0; i< macAddressLength; i++ ) {
		assert_int_equal(macAddressInHex[i], instance.macAddress[i]);
	}

	License_Destruct(&instance);
}

/**
 * generateClientInformationProcess test
 */
void Test_License_generateClientInformationProcess(void** State) {

	License instance;
	License_Construct(&instance);
	const unsigned char* interfaceName = "ens192";
	const unsigned char* aes256KeyPath = "../../../../Outputs/aes256Key.aes";
	const unsigned char* informationPath = "../../../../Outputs/content.info";
	instance.generateClientInformation(&instance, interfaceName, informationPath, aes256KeyPath);

	License_Destruct(&instance);
}



/**
 * generateAsymmetricKeyValuePairProcess test
 */
void Test_License_generateAsymmetricKeyValuePairProcess(void** State) {
	License instance;
	License_Construct(&instance);
	const unsigned char* path = "../../../../Outputs/license.key";
	instance.generateAsymmetricKeyValuePair(&instance, path);

	License_Destruct(&instance);
}

/**
 * generateLicenseProcess test
 */
void Test_License_generateLicenseProcess(void** State) {
	License instance;
	License_Construct(&instance);
	const unsigned char* interfaceName = "ens192";
	const unsigned char* aes256KeyPath = "../../../../Outputs/aes256Key.aes";
	const unsigned char* informationPath = "../../../../Outputs/content.info";
	const unsigned char* licensePrivateKeyPath = "../../../../Outputs/license.key.pem";
	const unsigned char* licensePath = "../../../../Outputs/license.lic";
	instance.generateLicense(&instance, interfaceName, informationPath, aes256KeyPath, licensePrivateKeyPath, licensePath, 365);

	License_Destruct(&instance);
}

/**
 * validateLicenseProcess test
 */
void Test_License_validateLicenseProcess(void** State) {
	License instance;
	License_Construct(&instance);
	const unsigned char* interfaceName = "ens192";
	const unsigned char* aes256KeyPath = "../../../../Outputs/aes256Key.aes";
	const unsigned char* licensePublicKeyPath = "../../../../Outputs/license.key.pub";
	const unsigned char* informationPath = "../../../../Outputs/license.lic";
	instance.validateLicense(&instance, interfaceName, licensePublicKeyPath, informationPath, aes256KeyPath);

	
	License_Destruct(&instance);
}

/**
 * Obtaining the MAC address
 *
 * @param interfaceName [const unsigned char*] The interface name of the NIC
 * @param macAddress [unsigned char*] The MAC address storage
 * @param macAddressLength [const unsigned int] The length of the MAC address storage
 * @return [char] The success flag; when the value is equal to 0x0, the process is success; otherwise, the process
 * is failure
 */
static char getMacAddress(const unsigned char* interfaceName, unsigned char* macAddress, const unsigned int macAddressLength) {
    // Obtaining the socket file descriptor
    int socketFileDescriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFileDescriptor == -1) {
        fprintf(stderr, "Socket function errors\n");
        return 0x1;
    }

    // Assigning the NIC name to the field of the interface request
    struct ifreq interfaceRequest;
    strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ - 1);
    interfaceRequest.ifr_name[IFNAMSIZ - 1] = '\0';

    // Determining if the MAC address can be obtained
    if (ioctl(socketFileDescriptor, SIOCGIFHWADDR, &interfaceRequest) == -1) {
        fprintf(stderr, "Function ioctl errors\n");
        close(socketFileDescriptor);
        return 0x1;
    }

    // Copying the MAC address which is described by 6 bytes
    memcpy(macAddress, interfaceRequest.ifr_hwaddr.sa_data, macAddressLength);
    close(socketFileDescriptor);
    return 0x0;
}
