#ifndef ACL_H
#define ACL_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "terminal_colours.h"

#define MAX_USERNAME_LENGTH 50
#define READ_PERMISSION 0x4   // 100 in binary
#define WRITE_PERMISSION 0x2  // 010 in binary
#define EXECUTE_PERMISSION 0x1  // 001 in binary

#define ALLOW 1
#define DENY 0

#define MAX_ACL_ENTRIES 100
#define MAX_PATH_LENGTH 256
#define MAX_PRINCIPAL_NAME 50
#define MAX_ACLS 100

//use relative path for ACL_FILENAME
#define ACL_FILENAME "path/to/src/file_permissions.txt"

extern char current_user[50];
// Mutex for synchronizing access to ACL data
pthread_mutex_t acl_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char principal[MAX_PRINCIPAL_NAME]; // User or group name
    int permissions;    // Bitmap of permissions (read, write, execute)
    int type;           // Allow or Deny
} ACLEntry;

typedef struct {
    char path[MAX_PATH_LENGTH];
    ACLEntry entries[MAX_ACL_ENTRIES];
    int entry_count;
} ACL;

// Assume a global list of ACLs
ACL acl_list[100];  // Adjust size as needed
int acl_count = 0;

// Function prototypes
void load_acls(const char* filename);
void save_acls(const char* filename);
int check_acl_permission(const char *path, const char *user, int operation);
ACL *get_acl_for_path(const char *path);
ACL* create_new_acl(const char *path);
int add_acl_entry(const char *path, const char *principal, int permissions, int type);
int remove_acl_entry(const char *path, const char *principal);
int manage_acl_entry(const char *path, const char *principal, const char *requester, int permissions, int type, int action);
void print_acl_entries(const ACL *acl);
void lock_acl();
void unlock_acl();

void lock_acl() {
    pthread_mutex_lock(&acl_mutex);
}

void unlock_acl() {
    pthread_mutex_unlock(&acl_mutex);
}

ACL* create_new_acl(const char *path) {
    // Assume there is a global array or list of ACLs: acl_list and a count: acl_count
    if (acl_count < MAX_ACLS) {
        strcpy(acl_list[acl_count].path, path);
        acl_list[acl_count].entry_count = 0;  // Initialize the entry count
        acl_count++;
        return &acl_list[acl_count - 1];
    }
    return NULL; // No space left for new ACLs
}

ACL *get_acl_for_path(const char *path) {
    // printf("Debug: About to access ACL for path %s\n", path);
    for (int i = 0; i < acl_count; i++) {
        if (strcmp(acl_list[i].path, path) == 0) {
            return &acl_list[i];
        }
    }
    return NULL; // No ACL found for the path
}

void load_acls(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open ACL file 1");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    while (fgets(line, sizeof(line), file) && acl_count < 100) {
        ACL new_acl = {0};  // Initialize new_acl to zero, especially the entry_count
        char *token = strtok(line, ",");
        if (token == NULL) {
            continue;  // Skip this line if no data
        }
        strncpy(new_acl.path, token, sizeof(new_acl.path) - 1);  // Copy path safely

        int entry_index = 0;  // Reset index for each new ACL
        while (entry_index < MAX_ACL_ENTRIES && (token = strtok(NULL, ",")) != NULL) {
            if (entry_index % 3 == 0) {  // Every three tokens cycle through principal, permissions, type
                strncpy(new_acl.entries[entry_index / 3].principal, token, sizeof(new_acl.entries[0].principal) - 1);
            } else if (entry_index % 3 == 1) {
                new_acl.entries[entry_index / 3].permissions = atoi(token);
            } else if (entry_index % 3 == 2) {
                new_acl.entries[entry_index / 3].type = atoi(token);
                new_acl.entry_count++;  // Only increment entry_count after a full entry is added
            }
            entry_index++;
        }

        if (new_acl.entry_count > 0) {
            acl_list[acl_count++] = new_acl;  // Only add to list if entries were successfully parsed
        }
    }
    fclose(file);
}


void save_acls(const char* filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open ACL file for writing");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < acl_count; i++) {
        ACL acl = acl_list[i];
        for (int j = 0; j < acl.entry_count; j++) {
            fprintf(file, "%s,%s,%d,%d\n", acl.path, acl.entries[j].principal,
                    acl.entries[j].permissions, acl.entries[j].type);
        }
    }
    fclose(file);
}


int check_acl_permission(const char *path, const char *user, int operation) {
    printf("checking permission for file at this path %s", path);
    lock_acl();
    ACL *acl = get_acl_for_path(path);
    if (!acl) {
        unlock_acl();
        return -EACCES; // Default to no access if no ACL is found
    }

    for (int i = 0; i < acl->entry_count; i++) {
        if (strcmp(acl->entries[i].principal, user) == 0 &&
            (acl->entries[i].permissions & operation) &&
            acl->entries[i].type == ALLOW) {
            unlock_acl();
            return 1; // Permission granted
        }
    }
    unlock_acl();
    return 0; // Permission denied
}

int add_acl_entry(const char *path, const char *principal, int permissions, int type) {
    lock_acl();  // Ensure thread safety

    int result = 0; // Default to failure
    ACL *acl = get_acl_for_path(path);
    if (!acl) {
        acl = create_new_acl(path);  // Assume this function creates a new ACL
        if (!acl) {
            unlock_acl();
            return 0; // Failure to create a new ACL
        }
    }

    // Check if an entry for the principal already exists
    for (int i = 0; i < acl->entry_count; i++) {
        if (strcmp(acl->entries[i].principal, principal) == 0) {
            // Update existing entry
            acl->entries[i].permissions = permissions;
            acl->entries[i].type = type;
            result = 1; // Success, existing entry updated
            break;
        }
    }

    if (result == 0 && acl->entry_count < MAX_ACL_ENTRIES) {  // No existing entry found; add new entry
        strcpy(acl->entries[acl->entry_count].principal, principal);
        acl->entries[acl->entry_count].permissions = permissions;
        acl->entries[acl->entry_count].type = type;
        acl->entry_count++;
        result = 1; // Success, new entry added
    }

    if (result == 1) {
        save_acls(ACL_FILENAME);  // Save changes to file
    }
    print_acl_entries(acl);  // Print ACL details before modification

    unlock_acl();
    return result;
}


void print_acl_entries(const ACL *acl) {
    if (acl == NULL) {
        printf("No ACL available to print.\n");
        return;
    }
    printf("ACL for path: %s, total entries: %d\n", acl->path, acl->entry_count);
    for (int i = 0; i < acl->entry_count; i++) {
        printf("Entry %d, Principal: %s, Permissions: %d, Type: %d\n",
               i, acl->entries[i].principal, acl->entries[i].permissions, acl->entries[i].type);
    }
}

int remove_acl_entry(const char *path, const char *principal) {
    printf("Attempting to remove ACL entry for user: %s on path: %s\n", principal, path);
    lock_acl();
    ACL *acl = get_acl_for_path(path);
    print_acl_entries(acl);
    if (!acl) {
        printf("No ACL found for path: %s\n", path);
        unlock_acl();
        return 0; // No ACL to remove from, fail
    }

    int found = 0;
    for (int i = 0; i < acl->entry_count; i++) {
        if (strcmp(acl->entries[i].principal, principal) == 0) {
            // Shift remaining entries
            for (int j = i; j < acl->entry_count - 1; j++) {
                acl->entries[j] = acl->entries[j + 1];
            }
            acl->entry_count--;
            found = 1; // Mark as found
            break; // Exit after shifting since we've removed the specific entry
        }
    }

    if (found) {
        save_acls(ACL_FILENAME);  // Save changes to file if an entry was successfully removed
    }

    unlock_acl();
    return found ? 1 : 0; // Return success if found and removed, otherwise failure
}

int manage_acl_entry(const char *path, const char *principal, const char *requester, int permissions, int type, int action) {
    // printf("manage acl entry was called\n");
    //  printf("these details were passed to add a new entry %s %s %s %i %i %i \n",path, principal, requester, permissions, type, action );

    // Ensure that the requester is the owner or has admin privileges
  
   ACL *acl = get_acl_for_path(path);
    if (!acl) {
        print_error("No ACL found for path: %s\n", path);
        return -ENOENT; // No ACL entry found
    }

    // Print comparison details
    if (acl->entry_count > 0) {
        printf("Comparing stored principal '%s' with requesting principal '%s'\n", acl->entries[0].principal, principal);
    } else {
        printf("No entries in ACL for path: %s\n", path);
    }
    if (!acl || strcmp(acl->entries[0].principal, principal) != 0) {
        printf("user %s, you are not the owner of this file \n", principal);
        return -EACCES; // Access denied if not the owner
    }

    if (action == 1) { // Add or update an ACL entry
    printf("adding new entry %s %s %i %i %i \n",path, requester, permissions, type, action );
        return add_acl_entry(path, requester, permissions, type);
    } else if (action == 0) { // Remove an ACL entry
        // printf("removing permissions for user %s \n", requester);
        return remove_acl_entry(path, requester);
    }
    return -EINVAL; // Invalid action
}


const char* permissions_to_string(int permissions) {
    static char str[4];
    str[0] = (permissions & READ_PERMISSION) ? 'r' : '-';
    str[1] = (permissions & WRITE_PERMISSION) ? 'w' : '-';
    str[2] = (permissions & EXECUTE_PERMISSION) ? 'x' : '-';
    str[3] = '\0';
    return str;
}

void debug_show_access() {
    printf("Access Control List (ACL) Entries:\n");
    for (int i = 0; i < acl_count; i++) {
        printf("File: %s\n", acl_list[i].path);
        for (int j = 0; j < acl_list[i].entry_count; j++) {
            printf("  User/Group: %s, Permissions: %s, Type: %s\n",
                   acl_list[i].entries[j].principal,
                   permissions_to_string(acl_list[i].entries[j].permissions),
                   acl_list[i].entries[j].type == ALLOW ? "Allow" : "Deny");
        }
        printf("\n");
    }
}


#endif // ACL_H