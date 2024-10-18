/**
 * @see License.h
 */
#include "../Headers/License.h"
// Public function
static char generateAES256Key(License*, const unsigned char*, const unsigned char*);
static char generateLicense(License*, const unsigned char*, const unsigned char*, const unsigned char*, const unsigned char*);
static char generateLicenseKey(License*, const unsigned char*, const unsigned char*, const unsigned char*);
static char validateLicense(License*, const unsigned char*, const unsigned char*, const unsigned char*);

// Private functions
static char getMacAddress(const unsigned char*, unsigned char*, const unsigned int);
static unsigned int encryptLicense(const unsigned char*, const unsigned char*, unsigned char*);
static char getSecretKey(const unsigned char*, unsigned char*, unsigned int);
static void applyPkcs7Padding(const unsigned char*, size_t, unsigned char**, size_t*);
static char aes256CbcEncrypt(const unsigned char*, size_t, const unsigned char*, unsigned char*, unsigned char**, size_t*);
static char isPkcs7PaddingValid(const unsigned char*, size_t);
static char aes256CbcDecrypt(const unsigned char*, size_t, const unsigned char*, unsigned char* iv, unsigned char**, size_t*);
static void execKeyValueParser(const unsigned char*, const unsigned int, const unsigned char**, const unsigned short, unsigned char**, const unsigned char*, const unsigned short, const unsigned char*, const unsigned short);

// The global variables, the fields are defined in a specified order; this will be used in the class License
const unsigned char* globalLicenseFields[] = {
    (const unsigned char*)LICENSE_CONTENT_MESSAGE_VARIABLE1,
    (const unsigned char*)LICENSE_CONTENT_MESSAGE_VARIABLE2,
    (const unsigned char*)LICENSE_CONTENT_MESSAGE_VARIABLE3,
    NULL};

/**
 * The constructor of the structure, License
 *
 * @param instance [License*] The instance from the License
 */
void License_Constrcut(License* instance) {
    // Dynamic memory allocation
    instance->valueForGlobalLicenseFields = NULL;
    instance->valueForGlobalLicenseFieldsLength = 0;
    // Calculating the array size
    for (unsigned int i = 0;
         globalLicenseFields[i] != NULL;
         i++) {
        (instance->valueForGlobalLicenseFieldsLength)++;
    }

    instance->valueForGlobalLicenseFields = calloc(instance->valueForGlobalLicenseFieldsLength, sizeof(unsigned char*));
    for (unsigned int i = 0; i < instance->valueForGlobalLicenseFieldsLength; i++) {
        // Assigned the memory
        (instance->valueForGlobalLicenseFields)[i] = calloc(LICENSE_LICENSE_CONTENTS_LENGTH, sizeof(unsigned char));
    }

    // Linking the function pointer to the function (public)
    instance->generateAES256Key = &generateAES256Key;
    instance->generateLicense = &generateLicense;
    instance->validateLicense = &validateLicense;
}

/**
 * The destructor of the structure, License
 */
void License_Destrcut(License* instance) {
    // Dynamic memory release
    if (instance->valueForGlobalLicenseFields != NULL) {
        for (unsigned int i = 0; i < instance->valueForGlobalLicenseFieldsLength; i++) {
            if ((instance->valueForGlobalLicenseFields)[i] != NULL) {
                free((instance->valueForGlobalLicenseFields)[i]);
                (instance->valueForGlobalLicenseFields)[i] = NULL;
            }
        }
        free(instance->valueForGlobalLicenseFields);
        instance->valueForGlobalLicenseFields = NULL;
    }

    // Destroying the function pointer
    instance->generateAES256Key = NULL;
    instance->generateLicense = NULL;
    instance->validateLicense = NULL;
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
 * @param interfaceName [const unsigned char*] The interface name of the NIC
 * @param deadline [const unsigned char*] The time in a string format, the format is "YYYY-mm-dd HH:MM:SS"
 * @param licensePath [const unsigned char*] The file path for reserving the key information of the license
 * @param aesKeyPath [const unsigned char*] The file path for reserving the aes key information of the AES key
 * @return [char] The success flag; when the value is equal to 0x0, the process is success; otherwise, the process
 * is failure
 */
static char generateLicense(License* instance,
                            const unsigned char* interfaceName,
                            const unsigned char* deadline,
                            const unsigned char* licensePath,
                            const unsigned char* aesKeyPath) {
    char isSuccess = 0x0;  // Now the flag is successful.

    // For reserving the length for the MAC and the storage itself
    enum { macAddressLength = 6 };
    unsigned char macAddress[macAddressLength] = {'\0'};

    // Obtaining the MAC address
    isSuccess = getMacAddress(interfaceName, macAddress, (const unsigned int)macAddressLength);
    if (isSuccess != 0x0) {  // When getMacAddress does not obtain the MAC address
        fprintf(stderr, "The function, getMacAddress, does not obtain the MAC address\n");
        return 0x1;
    }

    // Putting the MAC address into the field, secretKey
    unsigned char tmpBuffer[3] = {'\0'};
    for (unsigned int i = 0; i < macAddressLength; i++) {
        sprintf(tmpBuffer, "%02x", macAddress[i]);
        memcpy(instance->macAddress + (i * 2), tmpBuffer, 2);  // Copying the MAC address
    }

    // Fetching the local current time
    Time timeInstance;
    Time_Constrcut(&timeInstance);
    long currentTimeEpoch = timeInstance.getEpoch(&timeInstance, 0);  // Obtaining the current time (i.e., the second argument is equal to 0)
    long deadlineEpoch = timeInstance.getStringToEpoch(&timeInstance, (const char*)deadline);
    Time_Destrcut(&timeInstance);

    // The message format layout of the plaintext, assembling from the macro
    // const unsigned char* licenseMessage =
    //     LICENSE_CONTENT_MESSAGE_VARIABLE1 "%.*s\n" LICENSE_CONTENT_MESSAGE_VARIABLE2 "%lu\n" LICENSE_CONTENT_MESSAGE_VARIABLE3 "%lu\n";
    const unsigned char* licenseMessage = LICENSE_CONTENT_MESSAGE;

    // Printing the string into the memory
    unsigned int cumulativeLength = 0;
    cumulativeLength = sprintf(instance->licenseContents,
                               licenseMessage,
                               LICENSE_MAC_ADDRESS, instance->macAddress,  // %.*s
                               currentTimeEpoch,
                               deadlineEpoch);

    // Encrypting the message, obtaining the aes256 key
    isSuccess = getSecretKey(aesKeyPath, instance->secretKey, LICENSE_AES_KEY_SIZE);
    if (isSuccess != 0x0) {
        fprintf(stderr, "The function, getSecretKey, does not obtain the key information\n");
        return 0x1;
    }

    // Encrypting the message
    unsigned char* ciphertext = NULL;
    unsigned long ciphertextLength = 0;
    aes256CbcEncrypt((const unsigned char*)instance->licenseContents,
                     strlen((char*)instance->licenseContents),
                     instance->secretKey,
                     instance->iv,
                     &ciphertext,
                     &ciphertextLength);

    // Preparing the encrypted message format
    const unsigned char* encryptedLicenseMessage = "%.*s\n%.*s\n";
    cumulativeLength = 0;
    cumulativeLength = sprintf(instance->licenseContents,
                               encryptedLicenseMessage,
                               ciphertextLength, ciphertext,       // %.*s
                               LICENSE_AES_KEY_SIZE, instance->iv  // %.*s
    );

    // Generating the license file
    FILE* fileDescriptor = fopen((const char*)licensePath, "rb");
    if (fileDescriptor != NULL) {  // If the license file exists, ...
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    } else {  // If the license file does not exist, ...
        fileDescriptor = fopen((const char*)licensePath, "wb");
        fwrite(instance->licenseContents, sizeof(unsigned char), cumulativeLength, fileDescriptor);
    }

    // Releasing the file descriptor
    if (fileDescriptor != NULL) {
        fclose(fileDescriptor);
    }

    {  // Releasing the dynamic memory allocation
        if (ciphertext != NULL) {
            free(ciphertext);
            ciphertext = NULL;
        }
    }

    return isSuccess;
}

/**
 * Obtaining the secret key
 *
 * @param filePath [const unsigned char*] The key file path
 * @param key [unsigned char*] The buffer for reserving the key
 * @param keyLength[unsigned int] The length of the key
 * @return [char] The success flag; when the value is equal to 0x0, the process is success; otherwise, the process
 * is failure
 */
static char getSecretKey(const unsigned char* filePath, unsigned char* key, unsigned int keyLength) {
    char isSuccess = 0x0;
    // Opening the AES key file
    FILE* fileDescriptor = fopen((const char*)filePath, "rb");
    if (fileDescriptor == NULL) {
        fprintf(stderr, "The aes key file does not exist.\n");
        return (isSuccess = 0x1);
    }

    // Only one line shall be read.
    unsigned char temp[LICENSE_LICENSE_CONTENTS_LENGTH] = {'\0'};
    // "fgets(.)" will obtain n - 1 characters; that is when users feel like obtaining n
    // characters, the second argument in the fgets(.) shall be equal to n + 1
    if (fgets(temp, keyLength + 1, fileDescriptor) == NULL) {
        fprintf(stderr, "The aes key file does not exist.\n");
        return (isSuccess = 0x1);
    }
    // Copying the content to the memory, called key
    memcpy(key, temp, keyLength);
    return isSuccess;
}

/**
 * Pads the input data using PKCS#7 padding, the each padding content is the padding size
 *
 * @param data [const unsigned char*] The input data to be padded
 * @param dataLen [size_t] The length of the input data
 * @param paddedData [unsigned char**] A pointer to the output padded data, the pointer will refer to the dynamic memory allocation,
 * please release the memory manually after using the memory
 * @param paddedLen [size_t*] A pointer to the length of the output padded data
 */
static void applyPkcs7Padding(const unsigned char* data, size_t dataLen, unsigned char** paddedData, size_t* paddedLen) {
    // Calculating the number of padding size
    size_t paddingSize = LICENSE_BLOCK_SIZE - (dataLen % LICENSE_BLOCK_SIZE);

    *paddedLen = dataLen + paddingSize;
    *paddedData = calloc(*paddedLen, sizeof(unsigned char));
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
 * @param iv [unsigned char*] The AES initialization vector (16 bytes)
 * @param ciphertext [unsigned char*] The output buffer for the encrypted data
 * @param ciphertextLen [size_t*] A pointer to the length of the output ciphertext
 * @return [char] 0x0 on success, non-zero on failure
 */
static char aes256CbcEncrypt(const unsigned char* plaintext,
                             size_t plaintextLen,
                             const unsigned char* key,
                             unsigned char* iv,
                             unsigned char** ciphertext,
                             size_t* ciphertextLen) {
    gcry_cipher_hd_t cipher;
    unsigned char* paddedData = NULL;
    size_t paddedLen = 0;

    // Applying PKCS#7 padding
    applyPkcs7Padding(plaintext, plaintextLen, &paddedData, &paddedLen);

    // iv generation, using "gcry_randomize" for generating the random value;
    // the iv length is equal to LICENSE_BLOCK_SIZE; for the hex layout, the
    // editor declare the LICENSE_BLOCK_SIZE * 2 as the iv memory size
    gcry_randomize(iv, LICENSE_BLOCK_SIZE, GCRY_WEAK_RANDOM);

    // Initialize cipher
    gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(cipher, key, LICENSE_AES_KEY_SIZE);
    gcry_cipher_setiv(cipher, iv, LICENSE_BLOCK_SIZE);

    // When the returned cipher memory is NULL, ...
    if (*ciphertext == NULL) {
        *ciphertext = calloc(paddedLen * 2, sizeof(unsigned char));
    }

    unsigned char* originalCiphertext = calloc(paddedLen, sizeof(unsigned char));
    gcry_cipher_encrypt(cipher, originalCiphertext, paddedLen, paddedData, paddedLen);
    // Converting the hex value for the cipher
    unsigned long cumulativeLength = 0;
    unsigned long tmpLength = 0;
    unsigned char tmpBuff[3] = {'\0'};
    for (int i = 0; i < paddedLen; i++) {
        tmpLength = cumulativeLength;
        cumulativeLength += sprintf(tmpBuff, "%02x", originalCiphertext[i]);
        memcpy((*ciphertext) + tmpLength, tmpBuff, 2);
    }
    *ciphertextLen = cumulativeLength;

    // Converting the hex value for iv
    unsigned char* originalIV = calloc(LICENSE_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(originalIV, iv, LICENSE_BLOCK_SIZE);  // Copying the iv value into the temp storage
    cumulativeLength = tmpLength = 0;
    for (int i = 0; i < LICENSE_BLOCK_SIZE; i++) {
        tmpLength = cumulativeLength;
        cumulativeLength += sprintf(tmpBuff, "%02x", originalIV[i]);
        memcpy(iv + tmpLength, tmpBuff, 2);
    }

    // Removing the allocated memory from gcry(.)
    gcry_cipher_close(cipher);

    {  // Releasing the dynamic memory allocation
        if (paddedData != NULL) {
            free(paddedData);
            paddedData = NULL;
        }
        if (originalCiphertext != NULL) {
            free(originalCiphertext);
            originalCiphertext = NULL;
        }
        if (originalIV != NULL) {
            free(originalIV);
            originalIV = NULL;
        }
    }
    return 0x0;
}

/**
 * Decrypting the plaintext using AES-256-CBC with PKCS#7 padding
 *
 * @param ciphertext [const unsigned char*] The ciphertext data to be decrypted
 * @param ciphertextLen [size_t] The length of the ciphertext data
 * @param key [const unsigned char*] The AES encryption key (32 bytes for AES-256)
 * @param iv [unsigned char*] The AES initialization vector (16 bytes)
 * @param plaintext [unsigned char*] The output buffer for the decrypted data
 * @param plaintextLen [size_t*] A pointer to the length of the output plaintext
 * @return [char] 0x0 on success, non-zero on failure
 */
static char aes256CbcDecrypt(const unsigned char* ciphertext,
                             size_t ciphertextLen,
                             const unsigned char* key,
                             unsigned char* iv,
                             unsigned char** plaintext,
                             size_t* plaintextLen) {
    // Converting the hex value to the ciphertext
    // Assigning the memory allocation
    unsigned char* originalCiphertext = NULL;
    if (originalCiphertext == NULL) {
        originalCiphertext = calloc(ciphertextLen, sizeof(unsigned char));
    }

    // Using sscanf(.) to convert hex values into unsigned char string
    unsigned long cumulativeLength = 0;
    unsigned int tmpBuff = 0;  // For reserving the temporary memory
    for (int i = 0; i < ciphertextLen; i += 2) {
        // Parsing two characters as a hex value and converting the hex value to a decimal value
        sscanf(ciphertext + i, "%02x", &tmpBuff);
        originalCiphertext[cumulativeLength] = (unsigned char)tmpBuff;
        cumulativeLength++;
    }
    size_t paddedLen = 0;
    paddedLen = cumulativeLength;

    // Converting the hex value to iv
    unsigned char* originalIV = calloc(LICENSE_BLOCK_SIZE, sizeof(unsigned char));
    // memcpy(originalIV, iv, LICENSE_BLOCK_SIZE);  // Copying the iv value into the temp storage
    cumulativeLength = tmpBuff = 0;
    for (int i = 0; i < LICENSE_AES_KEY_SIZE; i += 2) {
        sscanf(iv + i, "%02x", &tmpBuff);
        originalIV[cumulativeLength] = (unsigned char)tmpBuff;
        cumulativeLength++;
    }
    // Copying the original iv to iv memory space
    memcpy(iv, originalIV, LICENSE_BLOCK_SIZE);

    // Decrypted process
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(handle, key, LICENSE_AES_KEY_SIZE);
    gcry_cipher_setiv(handle, iv, LICENSE_BLOCK_SIZE);

    // Generating the plaintext (containing the padding information) by decrypting the ciphertext
    unsigned char* paddedData = calloc(paddedLen, sizeof(unsigned char));
    gcry_cipher_decrypt(handle, paddedData, paddedLen, originalCiphertext, paddedLen);
    // Closing cipher handle
    gcry_cipher_close(handle);

    // Verifying if the data containing the PKCS#7 paddings
    char isPadding = isPkcs7PaddingValid((const unsigned char*)paddedData, paddedLen);
    // When the paddings exist, ...
    if (isPadding == 0x1) {
        paddedLen -= ((size_t)(paddedData[paddedLen - 1]));  // Calculating the length without considering the paddings'
        paddedData[paddedLen] = '\0';
    }

    // Preparing the returned memory
    if (*plaintext == NULL) {
        *plaintext = calloc(paddedLen + 1, sizeof(unsigned char));  // 1 is for '\0'
    }
    // Copying the contents and assigning the value
    memcpy(*plaintext, paddedData, (*plaintextLen = paddedLen));
    (*plaintext)[(*plaintextLen)] = '\0';

    {  // Memory deallocation
        if (originalCiphertext != NULL) {
            free(originalCiphertext);
            originalCiphertext = NULL;
        }

        if (originalIV != NULL) {
            free(originalIV);
            originalIV = NULL;
        }

        if (paddedData == NULL) {
            free(paddedData);
            paddedData = NULL;
        }
    }
    return 0x0;
}

/**
 * Determining the plaintext has been padded
 *
 * @param data [const unsigned char*] The plaintext determining if the paddings exists
 * @param datalength [size_t] The length of the plaintext
 * @return [char] 0x0 shows no paddings, otherwise, the returned value is equal to 0x1
 */
static char isPkcs7PaddingValid(const unsigned char* data, size_t dataLength) {
    // If there exist no data
    if (dataLength == 0) {
        return 0x0;
    }

    // Obtaining the last character for padding verification
    unsigned char paddingSize = data[dataLength - 1];

    // The padding value shall be between 1 and 15
    if ((int)paddingSize < 1 || (int)paddingSize > 16) {
        return 0x0;
    }

    // Verifying the last "paddingSize" characters; if those characters' values are the same, ...
    for (size_t i = dataLength - (size_t)paddingSize; i < dataLength; i++) {
        if (data[i] != paddingSize) {
            return 0x0;
        }
    }

    return 0x1;  // Paddings exist
}

/**
 * Generating the license key; the source is from the aesKey
 *
 * @param instance [License*] The license object
 * @param interfaceName [const unsigned char*] The interface name of the NIC
 * @param licensePath [const unsigned char*] The file path for reserving the key information of the license
 * @param aesKeyPath [const unsigned char*] The file path for reserving the aes key information of the AES key
 * @return [char] The success flag; when the value is equal to 0x0, the process is success; otherwise, the process
 * is failure
 */
static char validateLicense(License* instance,
                            const unsigned char* interfaceName,
                            const unsigned char* licensePath,
                            const unsigned char* aesKeyPath) {
    // Obtaining the information of the license
    FILE* fileDescriptor = fopen(licensePath, "rb");
    if (fileDescriptor == NULL) {
        fprintf(stderr, "The license does not exist.\n");
        return 0x1;
    }

    {  // Obtaining the contents of the license
        short counter = 0;
        unsigned char buffer[LICENSE_LICENSE_CONTENTS_LENGTH] = {'\0'};

        // Obtaining the content from a line
        while (fgets((char*)buffer, LICENSE_LICENSE_CONTENTS_LENGTH + 1, fileDescriptor) != NULL) {
            // Assigning the information to suitable variable
            unsigned long length = strlen(buffer);
            switch ((int)counter) {
                case 0:  // The information of the license contents
                    memcpy(instance->licenseContents, buffer, LICENSE_LICENSE_CONTENTS_LENGTH);
                    // Verifying the last element and last second element
                    (instance->licenseContents)[length - 1] = ((instance->licenseContents)[length - 1] == '\n') ? '\0' : (instance->licenseContents)[length - 1];
                    (instance->licenseContents)[length - 2] = ((instance->licenseContents)[length - 2] == '\n') ? '\0' : (instance->licenseContents)[length - 2];
                    break;
                case 1:  // The iv information
                    memcpy(instance->iv, buffer, LICENSE_AES_KEY_SIZE);
                    break;
            }
            counter++;
        }
    }

    // Closing the license file
    if (fileDescriptor != NULL) {
        fclose(fileDescriptor);
        fileDescriptor = NULL;
    }

    {  // Obtaining the key information
        // Encrypting the message, obtaining the aes256 key
        char isSuccess = getSecretKey(aesKeyPath, instance->secretKey, LICENSE_AES_KEY_SIZE);
        if (isSuccess != 0x0) {
            return 0x1;
        }
    }

    // Decrypting the message
    unsigned char* plaintext = NULL;  // The variable shall be deallocated manually
    size_t plaintextLen = 0;
    aes256CbcDecrypt((const unsigned char*)instance->licenseContents,
                     strlen((unsigned char*)instance->licenseContents),
                     (const unsigned char*)instance->secretKey,
                     instance->iv,
                     &plaintext,
                     &plaintextLen);
    // Parser definition
    const unsigned char* keyValueDelimiter = ":";
    const unsigned short keyValueDelimiterLength = (unsigned short)strlen((char*)keyValueDelimiter);
    const unsigned char* rowDelimiter = "\n";
    const unsigned short rowDelimiterLength = (unsigned short)strlen((char*)rowDelimiter);
    // Parsing the contents
    execKeyValueParser(plaintext, plaintextLen, globalLicenseFields, instance->valueForGlobalLicenseFieldsLength,
                       instance->valueForGlobalLicenseFields, keyValueDelimiter, keyValueDelimiterLength,
                       rowDelimiter, rowDelimiterLength);

    // Printing the result
    for (unsigned int i = 0; i < instance->valueForGlobalLicenseFieldsLength; i++) {
        fprintf(stderr, "%s\n", (instance->valueForGlobalLicenseFields)[i]);
    }

    {  // Memory deallocation
        if (plaintext != NULL) {
            free(plaintext);
            plaintext = NULL;
        }
    }
    return 0x0;
}

/**
 * Parsing the key value contents and putting the values into the memory in a specified field order
 *
 * @param content [const unsigned char*] The contents for parsing
 * @param contentLength [const unsigned int] The contents for parsing
 * @param fields [const unsigned char*] The key fields in an order which users specified
 * @param fieldsLength [const unsigned short] The length of the key field array
 * @param values [unsigned char*] The values which map from the value
 * @param keyValueDelimiter [const unsigned char*] Delimiter array; Delimiters between keys and values in the content
 * @param keyValueDelimiterLength [const unsigned short] The length of the delimiter array above
 * @param rowDelimiter [const unsigned char*] Row delimiter array; Row delimiters in the content
 * @param rowDelimiterLength [const unsigned short] The length of the row delimiter array
 */
static void execKeyValueParser(const unsigned char* content,
                               const unsigned int contentLength,
                               const unsigned char** fields,
                               const unsigned short fieldsLength,
                               unsigned char** values,
                               const unsigned char* keyValueDelimiter,
                               const unsigned short keyValueDelimiterLength,
                               const unsigned char* rowDelimiter,
                               const unsigned short rowDelimiterLength) {
    char keyValueFlag = 0x0;                       // 0x0 implies the parsed result belongs to a key;
                                                   // 0x1 implies the parsed result belongs to a value
    char isExisted = 0x0;                          // To distinguish whether the delimiter exists; 0x0: non-existence; 0x1: existence
    const unsigned char* delimiter = NULL;         // The value which the pointer refers can not be modified.
    const unsigned short* delimiterLength = NULL;  // The value which the pointer refers can not be modified.
    short keyIndex = -1;                           // For recording the index of the key when hitting the key field array

    unsigned char tempBuffer[LICENSE_LICENSE_CONTENTS_LENGTH] = {'\0'};
    // Contents traversal
    unsigned int i = 0, j = 0;
    for (; i < contentLength; i++) {
        if (keyValueFlag == 0x0) {  // Key searching process
            delimiter = keyValueDelimiter;
            delimiterLength = &keyValueDelimiterLength;
        } else {  // Value searching process
            delimiter = rowDelimiter;
            delimiterLength = &rowDelimiterLength;
        }

        isExisted = 0x0;
        for (unsigned short k = 0; k < *delimiterLength; k++) {
            if (content[i] == delimiter[k]) {  // If hitting the delimiter, ...
                isExisted = 0x1;
                break;
            }
        }
        // If the character of the content does not correspond to the delimiter, ...
        if (isExisted == 0x0) {
            continue;
        }

        // Obtaining the term, which can be a key or a value; now, using the term as a pivot to
        // verify if the pivot exists in the key field array
        // "isExisted = 0x1" case
        if (keyValueFlag == 0x0) {  // The key process; when the term belongs to the key, the term shall
                                    // include the delimiter between the key and the value
            memcpy(tempBuffer, content + j, (i - j + 1));
            tempBuffer[(i - j + 1)] = '\0';
        } else {  // The value term
            memcpy(tempBuffer, content + j, (i - j));
            tempBuffer[(i - j)] = '\0';
        }

        if (keyValueFlag == 0x0) {  // The key process
            keyIndex = -1;
            for (unsigned short k = 0; k < fieldsLength; k++) {
                if (strcmp((const char*)fields[k], (const char*)tempBuffer) == 0) {  // When the two string are equal, ...
                    keyIndex = k;                                                    // Reserving the index
                    break;
                }
            }
            keyValueFlag = 0x1;
        } else {  // The value process
            if (keyIndex >= 0) {
                // Copying the value from the tempBuffer memory to the proper value memory
                unsigned int stringLength = strlen((char*)tempBuffer);
                memcpy(values[keyIndex], tempBuffer, stringLength);
                values[keyIndex][stringLength] = '\0';
            }
            keyValueFlag = 0x0;
        }
        j = i + 1;  // Moving to the next term starting position
    }

    // If the last row has no row delimiter, the tempBuffer shall copy to the proper array, namely "values"
    if (i >= j && keyIndex >= 0) {
        unsigned int stringLength = strlen((char*)tempBuffer);
        memcpy(values[keyIndex], tempBuffer, stringLength);
        values[keyIndex][stringLength] = '\0';
    }
}