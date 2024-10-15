/**
 * @see License.h
 */
#include "../Headers/License.h"

static char generateAES256Key(License*, const unsigned char*, const unsigned char*);
static char getMacAddress(const unsigned char*, unsigned char*, const unsigned int);
static char generateLicenseKey(License*, const unsigned char*, const unsigned char*, const unsigned char*);
static void encryptLicense(const unsigned char*, const unsigned char*, unsigned char*);
static void applyPkcs7Padding(const unsigned char*, size_t, unsigned char**, size_t*);
static int aes256CbcEncrypt(const unsigned char*, size_t, const unsigned char*, const unsigned char*, unsigned char**, size_t*);

/**
 * The constructor of the structure, License
 *
 * @param instance [License*] The instance from the License
 */
void License_Constrcut(License* instance) {
    // Linking the function pointer to the function (public)
    instance->generateAES256Key = &generateAES256Key;
    instance->generateLicenseKey = &generateLicenseKey;
    instance->generateLicenseIntermediateKey = NULL;
}

/**
 * The destructor of the structure, License
 */
void License_Destrcut(License* instance) {
    // Destroying the function pointer
    instance->generateAES256Key = NULL;
    instance->generateLicenseKey = NULL;
    instance->generateLicenseIntermediateKey = NULL;
}

/**
 * Generating the AES key, the key will be modelled with the MAC address information with some random hex values;
 * after generating the key, the key value will be reserved into the file located in the path
 *
 * @param instance [License*] The license object
 * @param interfaceName [const unsigned char*] The string of the interface name of the NIC
 * @param path [const unsigned char*] The file path for reserving the key information of AES256
 * @return [char] The successful flag; when the value is 0x0, the generation is correct; otherwise, an error occurs
 */
static char generateAES256Key(License* instance, const unsigned char* interfaceName, const unsigned char* path) {
    // For reserving the length for the MAC and the storage itself
    enum { macAddressLength = 6 };
    unsigned char macAddress[macAddressLength] = {'\0'};

    char isSuccess = 0x0;  // Now the flag is successful.
    // Obtaining the MAC address
    isSuccess = getMacAddress(interfaceName, macAddress, (const unsigned int)macAddressLength);
    if (isSuccess != 0x0) {  // When getMacAddress does not obtain the MAC address
        fprintf(stderr, "The function, getMacAddress, does not obtain the MAC address\n");
        return 0x1;
    }

    // Putting the MAC address into the field, secretKey
    unsigned int cumulativeLength = 0;
    for (unsigned int i = 0; i < macAddressLength; i++) {
        cumulativeLength += sprintf((instance->secretKey) + cumulativeLength, "%02x", macAddress[i]);
    }
    memcpy(instance->macAddress, instance->secretKey, LICENSE_MAC_ADDRESS);  // Copying the MAC address

    // Padding by random hex values
    unsigned int remainderHexSize = ((unsigned int)LICENSE_AES_KEY_SIZE - cumulativeLength) / 2;
    // Preparing the buffer for the padding string, using the dynamic memory allocation
    unsigned char* randomBuffer = calloc(remainderHexSize, sizeof(unsigned char));
    // Using "gcry_randomize" for generating the random value
    gcry_randomize(randomBuffer, remainderHexSize, GCRY_WEAK_RANDOM);

    // To avoid the "\0" character when executing the last randomBuffer, this will lead the '\0' will be put in
    // the wrong memory location and be exceed the boundary.
    unsigned char tmpBuffer[3] = {'\0'};
    for (unsigned int i = 0, j = 0; i < remainderHexSize; i++) {
        j = sprintf(tmpBuffer, "%02x", randomBuffer[i]);
        memcpy((instance->secretKey) + cumulativeLength, tmpBuffer, 2);
        cumulativeLength += j;
    }

    // Releasing the dynamic memory allocation
    if (randomBuffer != NULL) {
        free(randomBuffer);
        randomBuffer = NULL;
    }

    // Swapping the odd bytes from the MAC address to the bytes from the last bytes of the randomBuffer
    // e.g., 005056b5474421e4712854cd53e43779 -> 9070763547e43154d1c85427e244b550
    for (unsigned int i = 0; i < remainderHexSize; i++) {
        // Exchanging the values
        instance->secretKey[i * 2] = instance->secretKey[i * 2] ^ instance->secretKey[LICENSE_AES_KEY_SIZE - i - 1];
        instance->secretKey[LICENSE_AES_KEY_SIZE - i - 1] = instance->secretKey[i * 2] ^ instance->secretKey[LICENSE_AES_KEY_SIZE - i - 1];
        instance->secretKey[i * 2] = instance->secretKey[i * 2] ^ instance->secretKey[LICENSE_AES_KEY_SIZE - i - 1];
    }

    // Key file generation
    FILE* fileDescriptor = fopen(path, "rb");
    if (fileDescriptor) {  // When the key file exists, ...
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    } else {  // When the key file does not exist, ...
        fileDescriptor = fopen(path, "wb");
        fwrite(instance->secretKey, sizeof(unsigned char), LICENSE_AES_KEY_SIZE, fileDescriptor);
    }

    if (fileDescriptor != NULL) {
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    }
    return 0x0;
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

/**
 * Generating the license key; the source is from the aesKey
 *
 * @param instance [License*] The license object
 * @param deadline [const unsigned char*] The time in a string format, the format is "YYYY-mm-dd HH:MM:SS"
 * @param aesKeyPath [const unsigned char*] The file path for reserving the aes key information of the AES key
 * @param licenseKeyPath [const unsigned char*] The file path for reserving the key information of the license
 * @return [char] The success flag; when the value is equal to 0x0, the process is success; otherwise, the process
 * is failure
 */
static char generateLicenseKey(License* instance,
                               const unsigned char* deadline,
                               const unsigned char* aesKeyPath,
                               const unsigned char* licenseKeyPath) {
    char isSuccess = 0x0;
    // Opening the aeskey
    FILE* fileDescriptor = fopen((const char*)aesKeyPath, "rb");
    if (fileDescriptor == NULL) {
        fprintf(stderr, "The aes key file does not exist.\n");
        return (isSuccess = 0x1);
    }

    // Only one line shall be read.
    unsigned char aesKey[LICENSE_AES_KEY_SIZE] = {'\0'};
    // "fgets(.)" will obtain n - 1 characters; that is when users feel like obtaining n
    // characters, the second argument in the fgets(.) shall be equal to n + 1
    if (fgets(aesKey, LICENSE_AES_KEY_SIZE + 1, fileDescriptor) == NULL) {
        fprintf(stderr, "The aes key file does not exist.\n");
        return (isSuccess = 0x1);
    }

    if (fileDescriptor != NULL) {
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    }

    // Fetching the local current time
    Time timeInstance;
    Time_Constrcut(&timeInstance);
    long currentTime = timeInstance.getEpoch(&timeInstance, 0);  // Obtaining the current time (i.e., the second argument is equal to 0)
    Time_Destrcut(&timeInstance);
    // Defining the license key
    unsigned char licenseKey[LICENSE_LICENSE_KEY_LENGTH] = {'\0'};
    memcpy(licenseKey, aesKey, LICENSE_AES_KEY_SIZE);  // Copying the AES key
    int cumulativeLength = LICENSE_AES_KEY_SIZE;
    {  // This block is organized like the TNS protocol (Oracle)
        // The string format of the current time
        unsigned char currentTimeString[16] = {'\0'};
        // The first length from calculating the currentTime
        int firstLength = sprintf(currentTimeString, "%lu", currentTime);
        // The second length from the first length above
        int secondLength = sprintf(currentTimeString, "%d", firstLength);
        // Adding the secondLength into the licenseKey storage
        cumulativeLength += sprintf(licenseKey + cumulativeLength, "%d", secondLength);
        // Adding the firstLength into the licenseKey storage
        cumulativeLength += sprintf(licenseKey + cumulativeLength, "%d", firstLength);
        // Adding the current time into the licenseKey storage
        cumulativeLength += sprintf(licenseKey + cumulativeLength, "%lu", currentTime);
    }

    // fprintf(stderr, "%d\n", cumulativeLength);

    // To ensure that the cumulativeLength now is even; otherwise, adding 0 after the length of the current licenseKey
    if (cumulativeLength % 2 != 0) {
        licenseKey[cumulativeLength] = '0';
        cumulativeLength++;
    }

    // Calculating the remainder size of the license key;
    // padding by random hex values
    unsigned int remainderHexSize = (unsigned int)(LICENSE_LICENSE_KEY_LENGTH - cumulativeLength) / 2;
    // Preparing the buffer for the padding string, using the dynamic memory allocation
    unsigned char* randomBuffer = calloc(remainderHexSize, sizeof(unsigned char));
    // Using "gcry_randomize" for generating the random value
    gcry_randomize(randomBuffer, remainderHexSize, GCRY_WEAK_RANDOM);

    // To avoid the "\0" character when executing the last randomBuffer, this will lead the '\0' will be put in
    // the wrong memory location and be exceed the boundary.
    unsigned char tmpBuffer[3] = {'\0'};
    for (unsigned int i = 0, j = 0; i < remainderHexSize; i++) {
        j = sprintf(tmpBuffer, "%02x", randomBuffer[i]);
        memcpy(licenseKey + cumulativeLength, tmpBuffer, 2);
        cumulativeLength += j;
    }

    // Releasing the dynamic memory allocation
    if (randomBuffer != NULL) {
        free(randomBuffer);
        randomBuffer = NULL;
    }

    // fprintf(stderr, "%.*s\n", LICENSE_LICENSE_KEY_LENGTH, licenseKey);

    // Swapping the ith byte from the first quarter of the data bytes from LICENSE_LICENSE_KEY, where i % 4 = 0;
    // the swapped byte is started from the (LICENSE_LICENSE_KEY/2)th byte
    for (unsigned int i = 0; i < LICENSE_LICENSE_KEY_LENGTH / 4; i++) {
        // Exchanging the values
        if (i % 4 == 0) {
            licenseKey[i] = licenseKey[i] ^ licenseKey[(LICENSE_LICENSE_KEY_LENGTH / 2) + i];
            licenseKey[(LICENSE_LICENSE_KEY_LENGTH / 2) + i] = licenseKey[i] ^ licenseKey[(LICENSE_LICENSE_KEY_LENGTH / 2) + i];
            licenseKey[i] = licenseKey[i] ^ licenseKey[(LICENSE_LICENSE_KEY_LENGTH / 2) + i];
        }
    }

    // fprintf(stderr, "%.*s\n", LICENSE_LICENSE_KEY_LENGTH, licenseKey);

    // License key file generation
    fileDescriptor = fopen(licenseKeyPath, "rb");
    if (fileDescriptor) {  // When the license key file exists, ...
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    } else {  // When the license key file does not exist, ...
        fileDescriptor = fopen(licenseKeyPath, "wb");
        fwrite(licenseKey, sizeof(unsigned char), LICENSE_LICENSE_KEY_LENGTH, fileDescriptor);
    }

    if (fileDescriptor != NULL) {
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    }

    return isSuccess;
}

/**
 * Encrypting the given plaintext using AES-256 encryption
 *
 * @param plaintext [const unsigned char*] The plaintext data to be encrypted.
 * @param key [const unsigned char*] The AES-256 encryption key (32 bytes).
 * @param ciphertext [unsigned char*] The buffer to store the encrypted ciphertext (16 bytes).
 */
static void encryptLicense(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext) {
    unsigned char plaintext2[LICENSE_BLOCK_SIZE] = {'\0'};
}

/**
 * Pads the input data using PKCS#7 padding
 *
 * @param data [const unsigned char*] The input data to be padded
 * @param dataLen [size_t] The length of the input data
 * @param paddedData [unsigned char**] A pointer to the output padded data
 * @param paddedLen [size_t*] A pointer to the length of the output padded data
 */
static void applyPkcs7Padding(const unsigned char* data, size_t dataLen, unsigned char** paddedData, size_t* paddedLen) {
    size_t paddingSize = LICENSE_BLOCK_SIZE - (dataLen % LICENSE_BLOCK_SIZE);
    *paddedLen = dataLen + paddingSize;
    *paddedData = (unsigned char*)malloc(*paddedLen);
    memcpy(*paddedData, data, dataLen);

    // PKCS#7 padding: each padded byte has the value of the padding size
    memset(*paddedData + dataLen, paddingSize, paddingSize);
}

/**
 * Encrypting the plaintext using AES-256-CBC with PKCS#7 padding
 *
 * @param plaintext [const unsigned char*] The plaintext data to be encrypted
 * @param plaintextLen [size_t] The length of the plaintext data
 * @param key [const unsigned char*] The AES encryption key (32 bytes for AES-256)
 * @param iv [const unsigned char*] The AES initialization vector (16 bytes)
 * @param ciphertext [unsigned char*] The output buffer for the encrypted data
 * @param ciphertextLen [size_t*] A pointer to the length of the output ciphertext
 * @return [char] 0x0 on success, non-zero on failure
 */
static int aes256CbcEncrypt(const unsigned char* plaintext,
                            size_t plaintextLen,
                            const unsigned char* key,
                            const unsigned char* iv,
                            unsigned char** ciphertext,
                            size_t* ciphertextLen) {
    gcry_cipher_hd_t cipher;
    unsigned char* paddedData = NULL;
    size_t paddedLen = 0;

    // Applying PKCS#7 padding
    applyPkcs7Padding(plaintext, plaintextLen, &paddedData, &paddedLen);

    // Initialize cipher
    gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(cipher, key, LICENSE_AES_KEY_SIZE);
    gcry_cipher_setiv(cipher, iv, LICENSE_BLOCK_SIZE);

    *ciphertext = (unsigned char*)malloc(paddedLen);
    gcry_cipher_encrypt(cipher, *ciphertext, paddedLen, paddedData, paddedLen);
    *ciphertextLen = paddedLen;

    // Removing the allocated memory
    gcry_cipher_close(cipher);
    free(paddedData);
    return 0;
}
