#ifndef HELPER_H
#define HELPER_H


#include <stdio.h>


#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_INPUT_LENGTH 50
#define SALT_LEN 16
#define HASH_ITERATIONS 10000
#define DEFAULT_KEY_LEN 32
#define HASH_LEN 32


int create_user(const char *username, const char *password);
char* get_current_user();
char* get_current_password();
void clear_input_buffer();
void trim_input(char *str);
char* get_input(char *prompt, char *buf, size_t size);
void hex_to_bin(const char *hex, unsigned char *bin, int bin_len);
int hash_password(const char *password, unsigned char *salt, unsigned char *hash);
void trim(char *str);



void trim_input(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) {  // All spaces?
        *str = '\0';  // Set string to empty
        return;
    }

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';  // Write new null terminator
}

char* get_input(char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    if (fgets(buf, size, stdin) == NULL)
        return NULL;

    if (buf[strlen(buf) - 1] != '\n') {
        // Input exceeded buffer, consume remaining characters
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    } else {
        // Properly null-terminate and remove newline
        buf[strlen(buf) - 1] = '\0';
    }

    trim_input(buf);  // Trim any leading/trailing whitespace
    return buf;
}

char* get_current_user() {
    static char username[MAX_INPUT_LENGTH];
    return get_input("Please enter your username:\n", username, sizeof(username));
}

char* get_current_password() {
    static char password[MAX_INPUT_LENGTH];
    struct termios old_term, new_term;

    printf("Please enter your password:\n");
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;

    // Disable echo in the terminal
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    //get password
    fgets(password, sizeof(password), stdin);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

    password[strcspn(password, "\n")] = 0; // Remove newline character
    printf("\n");

    return password;
}

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { } // Loop until the end of line or end of file
}





/**
 * @brief Function to convert hex string to binary
 * 
 * @param hex hex string
 * @param bin binary string
 * @param bin_len length of binary string
 */
void hex_to_bin(const char *hex, unsigned char *bin, int bin_len) {
    for (int i = 0; i < bin_len; i++) {
        sscanf(hex + (i * 2), "%02hhx", &bin[i]);
    }
}


/**
 * @brief Function to hash a password
 * 
 * @param password user's password
 * @param salt random salt
 * @param hash hashed password
 * @return int 
 */
int hash_password(const char *password, unsigned char *salt, unsigned char *hash) {
    // Generate a new random salt
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        return 0; // Failed to generate salt
    }

    // Use PBKDF2 to hash the password
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, SALT_LEN, HASH_ITERATIONS,
                           EVP_sha256(), DEFAULT_KEY_LEN, hash)) {
        return 0; // Hashing failed
    }

    return 1;
}

void trim(char *str) {
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)  // All spaces?
        return;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
   *(end+1) = 0;
}











#endif // HELPER_H