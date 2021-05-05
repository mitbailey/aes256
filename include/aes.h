/**
 * @file aes.h
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2021-05-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <openssl/evp.h>

// https://www.n-able.com/blog/aes-256-encryption-algorithm#:~:text=The%20National%20Institute%20of%20Standards,the%20strongest%20level%20of%20encryption.
#define AES_BLOCK_SIZE 128

/**
 * @brief Create a 256 bit key and IV.
 * 
 * Generates a key and IV given the supplied arguments.
 * Identical arguments will yield identical key and IV.
 * Also saves the 
 * 
 * @param key_data The key.
 * @param key_data_len Length of the key_data.
 * @param salt Can be added for taste.
 * @param e_ctx CTX encryption object, gets filled by aes_initialize().
 * @param d_ctx CTX decryption object, gets filled by aes_initialize().
 * @return int Negative on failure, 0 on success.
 */
int aes_initialize(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *ctx);

/**
 * @brief Encrypt data.
 * 
 *  All data going in and out is considered binary (unsigned char[]).
 * 
 * @param e A CTX structure, initialized with EVP_CIPHER_CTX_new()
 * @param plaintext Data to be encrypted.
 * @param len Length of plaintext.
 * @return unsigned char* The encrypted data.
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

/**
 * @brief Decrypt data.
 * 
 * All data going in and out is considered binary (unsigned char[]).
 * 
 * @param e A CTX structure, initialized with EVP_CIPHER_CTX_new()
 * @param ciphertext Data to be decrypted.
 * @param len Length of ciphertext.
 * @return unsigned char* The decrypted data.
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);