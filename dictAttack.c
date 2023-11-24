#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <time.h>


unsigned char plaintext[] = "ciaociaociaocia"; // 16 bytes or multipli

void padAesKey(char *line) {
    int requiredLength = 31;  // The desired length is 32 bytes

    int length = strlen((char *)line);

    if (length >= requiredLength) {
        // Key is already 32 bytes or longer, no need for padding
        return;
    }

    // Calculate the number of 'o' characters to add
    int dotsToAdd = requiredLength - length;

    // Add 'o' characters to the key to make it 32 bytes
    for (int i = length; i < requiredLength; i++) {
        line[i] = 'o';
    }
}

int main() {
    int tentativi = 0;
    // Prompt for input ciphertext in hexadecimal
    printf("Enter ciphertext (hexadecimal): ");
    char input[256];
    fgets(input, sizeof(input), stdin);

    // Remove trailing newline character
    input[strcspn(input, "\n")] = '\0';

    time_t current_time;
    time(&current_time);
    // Stampare l'ora corrente
    printf("Ora di inizio: %s", ctime(&current_time));

    // Convert the input hexadecimal ciphertext to binary
    int len = strlen(input) / 2;
    unsigned char binary_ciphertext[len];
    for (int i = 0; i < len; i++) {
        sscanf(input + i * 2, "%2hhx", &binary_ciphertext[i]);
    }

    FILE *fp;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t read;

    fp = fopen("rockyou2021.txt", "r");
    if (fp == NULL) {
        perror("Unable to open the file");
        return 1;
    }

    while ((read = getline(&line, &line_len, fp)) != -1) {
        line[strcspn(line, "\r\n")] = '\0'; // Remove trailing newline
      
        int aes_key_length = strlen((char *)line);
        if (aes_key_length > 31) {
            memset(line, 0, aes_key_length);
            continue;
        }
        
        if (aes_key_length < 31) {
            padAesKey(line);
        }
                
        // AES decryption context
        AES_KEY decrypt_key;
        AES_set_decrypt_key((unsigned char *)line, 256, &decrypt_key);

        // Initialize decryptedtext for this iteration
        unsigned char decryptedtext[16]; // Decrypted text
        memset(decryptedtext, 0, sizeof(decryptedtext));

        // Decrypt the ciphertext using the correct key
        AES_ecb_encrypt(binary_ciphertext, decryptedtext, &decrypt_key, AES_DECRYPT);


        // Check if the original plaintext matches the decrypted plaintext
        if (memcmp(plaintext, decryptedtext, sizeof(plaintext) - 1) == 0) {
            printf("CHIAVE TROVATA!!!\nLa chiave di cifratura e': %s\n", line);
            printf("Testo decifrato: %s\n", decryptedtext);
            time_t current_time;
            time(&current_time);
            // Stampare l'ora corrente
            printf("Ora di fine: %s", ctime(&current_time));
            printf("Numero totale di tentativi: %d\n", tentativi);
            break;
        }
        tentativi++;
        
    }
    printf("file letto correttamente fino alla fine");
    fclose(fp);
    if (line) {
        free(line);
    }

    return 0;
}
