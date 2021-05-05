/**
 * @file aes_extern.h
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2021-05-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Externally accessible...
// prime
// encrypt
// decrypt
// These should handle password, salt, etc. The user should
// only enter the data they want en/decrypted.

enum {
    ERR_SET_CTX = -10,
    ERR_AES_INIT,
    FAILURE = -1,
    SUCCESS = 1
};

/**
 * @brief Encrypts your data.
 * 
 * @param input The encryptable data.
 * @param len The length of the data.
 * @return unsigned char* Encrypted data.
 */
int aes_encrypt_data(char* input, uint8_t inputLength, char* output, uint8_t outputLength);

/**
 * @brief Decrypts your data.
 * 
 * @param input The decryptable data.
 * @param len The length of the data.
 * @return unsigned char* Decrypted data.
 */
int aes_decrypt_data(char* input, uint8_t inputLength, char* output, uint8_t outputLength);