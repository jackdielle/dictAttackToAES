#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

// Key for AES encryption 
static unsigned char aes_key[32]; // 32-byte key

// Function to pad the key to 32 bytes with dots if necessary
void padAesKey() {
    int requiredLength = 31;  // The desired length is 32 bytes

    int length = strlen((char *)aes_key);
    printf("Key before padding: %s\n", aes_key);

    if (length >= requiredLength) {
        // Key is already 32 bytes or longer, no need for padding
        return;
    }

    // Calculate the number of 'o' characters to add
    int dotsToAdd = requiredLength - length;

    // Add 'o' characters to the key to make it 32 bytes
    for (int i = length; i < requiredLength; i++) {
        aes_key[i] = 'o';
    }

    printf("Key after padding: %s\n", aes_key);
    printf("chiave con padding: %s\n", aes_key);
}


int main() {
    AES_KEY encrypt_key;
    unsigned char text[128]; // Input text
    unsigned char ciphertext[128]; // Encrypted text (hexadecimal)

    // Initialize the AES key with the original value
    strncpy((char *)aes_key, "ciao", 32);

    // Prompt for input text
    printf("Enter text to encrypt: ");
    fgets((char *)text, sizeof(text), stdin);

    // Pad the AES key to 32 bytes if needed
    int aes_key_length = strlen((char *)aes_key);
    if (aes_key_length < 31) {
        padAesKey();
    }

    // Initialize the encryption key
    if (AES_set_encrypt_key(aes_key, 256, &encrypt_key) < 0) {
        fprintf(stderr, "AES_set_encrypt_key failed\n");
        return 1;
    }

    AES_ecb_encrypt(text, ciphertext, &encrypt_key, AES_ENCRYPT);

    // Print the ciphertext in hexadecimal
    printf("Encrypted text (hexadecimal): ");
    for (int i = 0; i < strlen((char *)text); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
