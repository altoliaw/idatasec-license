/**
 * @see License.h
 */
#include "../Headers/License.h"

static void generateLicenseKey(License*, unsigned char*, const unsigned char*, unsigned int);
static void encryptLicense(const unsigned char*, const unsigned char*, unsigned char*);
static void formatAsUuidV4(const unsigned char* encryptedData, unsigned char* uuidStr);

/**
 * The constructor of the structure, License
 *
 * @param instance [License*] The instance from the License
 * @return [void]
 */
void License_Constrcut(License* instance) {
    (instance->encryptedKey)[0] = '\0';
    // Linking the function pointer to the function
    instance->generateLicenseIntermediateKey = NULL;
    instance->generateLicenseKey = &generateLicenseKey;
}

/**
 * The destructor of the structure, License
 */
void License_Destrcut(License* instance) {
    (instance->encryptedKey)[0] = '\0';
    // Destroying the function pointer
    instance->generateLicenseIntermediateKey = NULL;
    instance->generateLicenseKey = NULL;
}

/**
 * To generate the license
 *
 * @param instance [License*] The license object
 * @param licenseKey [unsigned char*]  The plaintext for the license key (37 bytes)
 * @param aesKey [const unsigned char*] The key for AES approach
 * @param days [unsigned int] The days for the active state
 */
static void generateLicenseKey(License* instance, unsigned char* licenseKey, const unsigned char* aesKey, unsigned int days) {
    time_t expiryTime = time(NULL) + (days * 24 * 3600);  // The arrived time
    unsigned char dataToEncrypt[BLOCK_SIZE] = {'\0'};     // The plaintext of the UUID + arrived time, 16 bytes
    snprintf(dataToEncrypt, sizeof(dataToEncrypt), "%ld", expiryTime);

    // The result for encryption
    unsigned char encryptedData[BLOCK_SIZE] = {'\0'};  // The 16-byte encrypted result
    encryptLicense(dataToEncrypt, aesKey, encryptedData);
    // fprintf(stderr, "%s\t %s\n", dataToEncrypt, encryptedData);

    // // Transforming encrypted data into the format of the UUID v4
    formatAsUuidV4(encryptedData, licenseKey);
}

/**
 * Encrypting the given plaintext using AES-256 encryption in ECB mode with zeros paddings.
 *
 * @param plaintext [const unsigned char*] The plaintext data to be encrypted.
 * @param key [const unsigned char*] The AES-256 encryption key (32 bytes).
 * @param ciphertext [unsigned char*] The buffer to store the encrypted ciphertext (16 bytes).
 */
static void encryptLicense(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext) {
    unsigned char plaintext2[BLOCK_SIZE] = {'\0'};

    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(handle, key, AES_KEY_SIZE);

    // AES encryption (ECB mode, with zero paddings)
    gcry_cipher_encrypt(handle, ciphertext, BLOCK_SIZE, plaintext, BLOCK_SIZE);
    gcry_cipher_close(handle);
}


/**
 * Formatting the encrypted data as a UUID v4 string.
 *
 * @param encryptedData [const unsigned char*] The 16-byte encrypted data.
 * @param uuidStr [unsigned char*] The buffer to store the formatted UUID string (must be at least 37 characters).
 */
static void formatAsUuidV4(const unsigned char* encryptedData, unsigned char* uuidStr) {
    snprintf(uuidStr, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        encryptedData[0], encryptedData[1], encryptedData[2], encryptedData[3],
        encryptedData[4], encryptedData[5],
        (encryptedData[6] & 0x0F) | 0x40, // Ensuring that the 7th byte is equal to '4' because of UUID v4 theory
        encryptedData[7],
        (encryptedData[8] & 0x3F) | 0x80, // Ensuring that the 9th byte of the UUID is the variant
        encryptedData[9],
        encryptedData[10], encryptedData[11], encryptedData[12],
        encryptedData[13], encryptedData[14], encryptedData[15]);
}