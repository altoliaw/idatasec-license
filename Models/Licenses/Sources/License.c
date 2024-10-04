/**
 * @see License.h
 */
#include "../Headers/License.h"

static void generateLicenseKey(License*, unsigned char*, const unsigned char*, unsigned int);
static void encryptLicense(const unsigned char*, const unsigned char*, unsigned char*);

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
 * @param licenseKey [unsigned char*]  The plaintext for the license key
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
    fprintf(stderr, "%s\n", dataToEncrypt);

    // // 將加密後的數據格式化為 UUID v4
    // formatAsUuidV4(encryptedData, licenseKey);
}

/**
 * @brief Encrypts the given plaintext using AES-256 encryption in ECB mode.
 *
 * @param plaintext [] The plaintext data to be encrypted.
 * @param key [] The AES-256 encryption key (32 bytes).
 * @param ciphertext [] The buffer to store the encrypted ciphertext (16 bytes).
 */
static void encryptLicense(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext) {
    gcry_cipher_hd_t handle;
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(handle, key, AES_KEY_SIZE);

    // AES encryption (ECB mode)
    gcry_cipher_encrypt(handle, ciphertext, BLOCK_SIZE, plaintext, BLOCK_SIZE);
    gcry_cipher_close(handle);
}