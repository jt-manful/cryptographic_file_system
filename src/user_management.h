#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "encryption_key.h"
#include "acl.h"
#include "helper.h"


#define MAX_USERS 20
#define FILENAME "user_accounts.txt"

// user structure to store user information
typedef struct {
    char username[50];
    unsigned char hash[50];
    unsigned char salt[SALT_LEN];
    unsigned char key[32];
} User;

// global var to extract user's encryption key
unsigned char session_key[DEFAULT_KEY_LEN];

// Array to store user accounts
User users[MAX_USERS];
int num_users = 0;



/**
 * @brief Function to authenticate a user
 * 
 * @param username user's registered username
 * @param provided_password corresponding password
 * @return int 
 */
int authenticate_user(const char *username, const char *provided_password) {

    unsigned char computed_hash[HASH_LEN];
    int i;

    
    for (int i = 0; i < num_users; i++) {
        trim(users[i].username);    
        if (strcmp(users[i].username, username) == 0) {
            unsigned char computed_hash[DEFAULT_KEY_LEN];
            if (!PKCS5_PBKDF2_HMAC(provided_password, strlen(provided_password),
                                   users[i].salt, SALT_LEN, HASH_ITERATIONS,
                                   EVP_sha256(), HASH_LEN, computed_hash)) {

                // Log the computed hash and salt for debugging
                printf("Authentication: Computed Salt and Hash for %s\n", username);
                printf("Salt: ");
                for (int i = 0; i < SALT_LEN; i++) {
                    printf("%02x", users[i].salt[i]);
                }
                printf("\nHash: ");
                for (int i = 0; i < DEFAULT_KEY_LEN; i++) {
                    printf("%02x", computed_hash[i]);
                }
                printf("\n");
                return 0;
            }
            if (memcmp(computed_hash, users[i].hash, DEFAULT_KEY_LEN) == 0) {

                memcpy(session_key, users[i].key, DEFAULT_KEY_LEN);

                // Print the session_key to verify correct retrieval
                printf("Session Key after authentication: ");
                for (int j = 0; j < DEFAULT_KEY_LEN; j++) {
                    printf("%02x", session_key[j]);
                }
                printf("\n");


                return 1; // Authentication successful
            } else {
                return 0; // Authentication failed
            }
        }
    }
    return 0; // User not found
}

/**
 * @brief Function to save user accounts to a file
 * 
 */
void save_user_accounts() {
    FILE *file = fopen(FILENAME, "w");
    if (!file) {
        perror("Error opening file\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_users; i++) {

        char hex_salt[2 * SALT_LEN + 1];
        char hex_hash[2 * DEFAULT_KEY_LEN + 1];
        char hex_key[2 * DEFAULT_KEY_LEN + 1]; 

        // Convert binary salt and hash to hex
        for (int j = 0; j < SALT_LEN; j++) {
            sprintf(hex_salt + j * 2, "%02x", users[i].salt[j]);
        }
        hex_salt[2 * SALT_LEN] = '\0';

        for (int j = 0; j < HASH_LEN; j++) {
            sprintf(hex_hash + j * 2, "%02x", users[i].hash[j]);
        }
        hex_hash[2 * DEFAULT_KEY_LEN] = '\0';

        for (int j = 0; j < DEFAULT_KEY_LEN; j++) {
            sprintf(hex_key + j * 2, "%02x", users[i].key[j]);
        }
        hex_key[2 * DEFAULT_KEY_LEN] = '\0';

        fprintf(file, "%s,%s,%s,%s\n", users[i].username, hex_hash, hex_salt, hex_key);
    }

    fclose(file);
}


/**
 * @brief Function to create a new user account
 * 
 * @param username user's username
 * @param password user's password
 * @return int 
 */
int create_user(const char *username, const char *password) {
    if (num_users >= MAX_USERS) {
        // Maximum number of users reached
        return 0;
    }

    User *new_user = &users[num_users];
    strcpy(new_user->username, username);

    if (!hash_password(password, new_user->salt, new_user->hash)) {
        fprintf(stderr, "Failed to hash password.\n");
        return 0;
    }

    if (RAND_bytes(new_user->key, DEFAULT_KEY_LEN) != 1) {
        fprintf(stderr, "Failed to generate encryption key.\n");
        return 0;
    }

    printf("Generated Key: ");
    for (int i = 0; i < DEFAULT_KEY_LEN; i++) {
        printf("%02x", new_user->key[i]);
    }
    printf("\n");
    
    num_users++;

    if (!add_acl_entry("path/to/src", username, READ_PERMISSION | WRITE_PERMISSION | EXECUTE_PERMISSION, ALLOW)) {
        print_error("Failed to set ACL for new user %s\n", username);
        return 0; // Return failure if ACL could not be added
    }

    save_user_accounts();
    return 1; // User account created successfully
}


/**
 * @brief Function to load user accounts from a file
 * 
 */
void load_user_accounts() {
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL) {
        // Parse user account data from line
        char *username = strtok(line, ",");
        char *hashed_password = strtok(NULL, ",");
        char *hex_salt = strtok(NULL, ",");
        char *key = strtok(NULL, "\n");

        if (username && hashed_password && hex_salt && key && num_users < MAX_USERS) {
            // Add user account to array
            strcpy(users[num_users].username, username);
            hex_to_bin(hashed_password, (unsigned char*)users[num_users].hash, DEFAULT_KEY_LEN);
            hex_to_bin(hex_salt, users[num_users].salt, SALT_LEN);
            hex_to_bin(key, users[num_users].key, DEFAULT_KEY_LEN);
            // strcpy(users[num_users].key, key);
            num_users++;
        }
    }

    fclose(file);
}



/**
 * Checks if a user with the given username exists.
 *
 * @param username The username to check.
 * @return 1 if the user exists, 0 otherwise.
 */
int user_exists(const char *username) {
    for (int i = 0; i < num_users; ++i) {
        if (strcmp(users[i].username, username) == 0) {
            return 1; // User exists
        }
    }
    return 0; // User does not exist
}

/**
 * @brief Function to get the decryption key of a user
 * 
 * @param current_user user's username
 * @param key key to be returned
 * @return int 
 */
int get_user_decryption_key(const char *current_user, unsigned char *key) {
    for (int i = 0; i < num_users; i++) {
        if (strcmp(users[i].username, current_user) == 0) {
            memcpy(key, users[i].key, DEFAULT_KEY_LEN);
            return 0; // Success
        }
    }
    return -1; // User not found or key not available
}


void initialize_user_management() {
    load_user_accounts();
}