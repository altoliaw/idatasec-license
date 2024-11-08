/**
 * @see EncodeBase64.h
 */
#include "../Headers/EncodeBase64.h"

static char base64Encode(const unsigned char*, const unsigned long, unsigned char**, unsigned long*);
static char base64Decode(const unsigned char*, const unsigned long, unsigned char**, unsigned long*);


// Lookup table for Base64 encoding transformation
static const unsigned char base64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Inverse transformation table for Base64 decoding operations
static const unsigned char base64DecodeTable[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * Constructor
 *
 * @param instance [EncodeBase64*] The instance of the EncodeBase64
 */
void EncodeBase64_Construct(EncodeBase64* instance) {
    EncodePrototype_Construct(&(instance->parent), (const unsigned char*)"EncodeBase64");
    (instance->parent).encodeString = &base64Encode;
	(instance->parent).decodeString = &base64Decode;
}

/**
 * Destructor
 *
 * @param instance [EncodeBase64*] The instance of the EncodeBase64
 */
void EncodeBase64_Destruct(EncodeBase64* instance) {
    EncodePrototype_Destruct(&(instance->parent));
}

/**
 *
 * This implementation follows RFC 4648 specifications for Base64 encoding.
 * The algorithm processes input data in 3-byte blocks, producing 4 output characters
 * for each block. Padding is automatically applied when input length is not
 * divisible by 3.
 *
 * @param data [const unsigned char*] Pointer to the input binary data buffer
 * @param dataLen [size_t] Length of the input data in bytes
 * @param output [unsigned char**] The encoded result's memory; the memory shall be release by the caller outside
 * @param outputLen [size_t*] Pointer to store the length of encoded output
 * @return [char] 0x0 implies success; 0x1 implies failure
 */
static char base64Encode(const unsigned char* data, const unsigned long dataLen, unsigned char** output, unsigned long* outputLen) {
    // Calculating the required length for encoded output (ceil(n/3) * 4)
    unsigned long encodedLen = ((dataLen + 2) / 3) * 4;
    if (*output == NULL) {
        *output = calloc(encodedLen + 1, sizeof(unsigned char));  // Additional byte for null terminator
    }
    
    unsigned long i, j = 0;
    for (i = 0; i < dataLen; i += 3) {
        // Combining three bytes into a 24-bit buffer
        unsigned int val = data[i] << 16;
        if (i + 1 < dataLen) val |= data[i + 1] << 8;
        if (i + 2 < dataLen) val |= data[i + 2];

        // Extracting 6-bit segments and mapping to Base64 alphabet
        (*output)[j++] = base64Table[(val >> 18) & 0x3f];
        (*output)[j++] = base64Table[(val >> 12) & 0x3f];
        (*output)[j++] = (i + 1 < dataLen) ? base64Table[(val >> 6) & 0x3f] : '=';
        (*output)[j++] = (i + 2 < dataLen) ? base64Table[val & 0x3f] : '=';
    }

    (*output)[j] = '\0';
    *outputLen = j;
    return 0x0;
}

/**
 *
 * Implementation of the inverse transformation of Base64 encoding as specified in RFC 4648;
 * the algorithm processes input in 4-character blocks, producing 3 bytes of binary
 * output for each block; handling padding characters ('=') appropriately
 *
 * @param encodedData [const unsigned char*] Pointer to the Base64 encoded input string
 * @param encodedLen [const unsigned long] Length of the encoded input string
 * @param decodedData [const unsigned char**] The decoded string; the memory shall be released by the caller outside
 * @param outLen [unsigned long*] Pointer to store the length of decoded output
 * @return [char] 0x0 implies success; 0x1 implies failure
 */
static char base64Decode(const unsigned char* encodedData, const unsigned long encodedLen, unsigned char** decodedData, unsigned long* outLen) {
    // Validate input length (must be multiple of 4)
    if (encodedLen % 4 != 0) {
        *outLen = 0;
        return 0x1;
    }

    // Calculate padding length and actual output size
    unsigned long padding = 0;
    if (encodedLen > 0 && encodedData[encodedLen - 1] == '=') {
		padding++;
	}
    if (encodedLen > 1 && encodedData[encodedLen - 2] == '=') {
		padding++;
	}

	// Calculating the length
    *outLen = (encodedLen / 4) * 3 - padding;

    if (*decodedData == NULL) {
		*decodedData = calloc((size_t)(*outLen), sizeof(unsigned char));
    }

    size_t i, j = 0;
    for (i = 0; i < encodedLen; i += 4) {
        // Reconstructing 24-bit groups from Base64 characters
        unsigned int val =
            (base64DecodeTable[(unsigned char)encodedData[i]] << 18) |
            (base64DecodeTable[(unsigned char)encodedData[i + 1]] << 12);

        // Extracting first byte
        (*decodedData)[j++] = (val >> 16) & 0xff;

        // Handling remaining bytes considering padding
        if (encodedData[i + 2] != '=') {
            val |= base64DecodeTable[(unsigned char)encodedData[i + 2]] << 6;
            (*decodedData)[j++] = (val >> 8) & 0xff;

            if (encodedData[i + 3] != '=') {
                val |= base64DecodeTable[(unsigned char)encodedData[i + 3]];
                (*decodedData)[j++] = val & 0xff;
            }
        }
    }

    return 0x0;
}