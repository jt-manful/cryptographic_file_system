/**
 * @file mycfs.c
 * @brief Implementation of a cryptographic file system using FUSE (Filesystem in Userspace).
 *
 * This file contains the implementation of various file system operations such as
 * reading, writing, creating, deleting files and directories, and listing directory contents.
 * It also includes functions for encrypting and decrypting file data using AES encryption.
 * The file system enforces access control using Access Control Lists (ACLs) and requires user authentication.
 * The implementation is based on the FUSE library and OpenSSL for cryptographic operations.
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h> 
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <termios.h>
#include "user_management.h"
#include "terminal_colours.h"
#include "acl.h"
#include "helper.h"


char current_user[MAX_USERNAME_LENGTH];
char current_password[MAX_PASSWORD_LENGTH];

static int cfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
static int cfs_mkdir(const char *path, mode_t mode);
static int cfs_unlink(const char *path);
static int cfs_truncate(const char *path, off_t size, struct fuse_file_info *fi);
static int cfs_rmdir(const char *path);
static int cfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi);
static int cfs_rename(const char *oldpath, const char *newpath, unsigned int flags);

static struct fuse_operations cfs_oper = {
    .getattr    = cfs_getattr,
    .read       = cfs_read,
    .write      = cfs_write,
    .readdir    = cfs_readdir,
    .create     = cfs_create,
    .mkdir      = cfs_mkdir,
    .unlink     = cfs_unlink,
    .truncate   = cfs_truncate,
    .rmdir      = cfs_rmdir,
    .utimens    = cfs_utimens,
    .rename     = cfs_rename,
};


/**
 * Updates the access and modification times of a file or directory.
 *
 * This function is called by the FUSE library when the utimens system call is invoked
 * on a file or directory within the mounted filesystem.
 *
 * @param path The path of the file or directory.
 * @param ts An array of two timespec structures representing the new access and modification times.
 * @param fi File information. Unused in this implementation.
 * @return 0 on success, or a negative error code on failure.
 */
static int cfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
    (void) fi; 

    // Update the times on the filesystem or underlying storage.
    int res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1) {
        return -errno;
    }
    return 0;
}


/**
 * Retrieves the attributes of a file or directory specified by the given path.
 *
 * @param path The path of the file or directory.
 * @param stbuf Pointer to the struct where the attributes will be stored.
 * @param fi File information (unused in this implementation).
 * @return 0 on success, or a negative error code on failure.
 */
static int cfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    int res = 0;
    (void) fi;

    memset(stbuf, 0, sizeof(struct stat));

    res = stat(path, stbuf);
    // If file/directory not found, return -errno
    if (res == -1)
        return -errno;

    return 0;
}

/**
 * Reads data from a file specified by the given path.
 *
 * @param path The path of the file.
 * @param buf Pointer to the buffer where the read data will be stored.
 * @param size The maximum number of bytes to read.
 * @param offset The offset within the file to start reading from.
 * @param fi File information (unused in this implementation).
 * @return The number of bytes read on success, or a negative error code on failure.
 */
static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int fd;
    int res;

    unsigned char *ciphertext;
    unsigned char *plaintext;

    ciphertext = malloc(size);
    if (!ciphertext) {
        return -ENOMEM;
    }

    (void) fi;

    if (!check_acl_permission(path, current_user, READ_PERMISSION)) {
        print_error("user %s you dont have access to read from this file", current_user);
        return -EACCES;
    }
    fd = open(path, O_RDONLY);
    if (fd == -1){
        free(ciphertext);
        return -errno;
    }

    res = pread(fd, ciphertext, size, offset);
    if (res == -1){
        res = -errno;
        close(fd);
        free(ciphertext);
        return res;
    }
    close(fd);
    
    plaintext = malloc(size); //allocating space for decryption
    if (!plaintext) {
        free(ciphertext);
        return -ENOMEM;
    }

    //decrypt the data
    int plaintext_len = decrypt_data(ciphertext, res, session_key, plaintext);
    if (plaintext_len < 0) {
        free(ciphertext);
        free(plaintext);
        return -EIO; // Decryption failed
    }

    // append decrypted data to the user buffer
    memcpy(buf, plaintext, plaintext_len);

    // Clean up
    free(ciphertext);
    free(plaintext);

    return plaintext_len;
}

// static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
//     int fd;
//     int res;

//     (void) fi; // Avoid unused parameter warning
//     fd = open(path, O_RDONLY);
//     if (fd == -1)
//         return -errno;

//     res = pread(fd, buf, size, offset);
//     if (res == -1) {
//         res = -errno;
//     }

//     close(fd);
//     return res;
// }

/**
 * @brief Writes data to a file.
 * 
 * This function writes the specified data to a file at the given path. It first checks the access control list (ACL) permission to ensure that the current user has write permission for the file. If the user does not have write permission, an access denied error (-EACCES) is returned. 
 * 
 * The function then encrypts the data using a session key and writes the encrypted data to the file. It prints the session key used for encryption and the ciphertext to the console for debugging purposes.
 * 
 * @param path The path of the file to write to.
 * @param buf The buffer containing the data to write.
 * @param size The size of the data to write.
 * @param offset The offset in the file where the data should be written.
 * @param fi The file information.
 * @return On success, the number of bytes written is returned. On error, a negative value is returned.
 */
static int cfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int fd;
    int res;
    unsigned char *ciphertext;

    ciphertext = malloc(size + AES_BLOCK_SIZE);
    if(!ciphertext){
        return -ENOMEM;
    }

    if (!check_acl_permission(path, current_user, WRITE_PERMISSION)) {
        printf("user %s you dont have access to write to this file", current_user);
        return -EACCES;
    }

    printf("Session key used for encryption: ");
    for (int i = 0; i < DEFAULT_KEY_LEN; i++) {
        printf("%02x", session_key[i]);
    }
    printf("\n");

    int ciphertext_len = encrypt_data((const unsigned char *)buf, size, session_key, ciphertext);
    if (ciphertext_len < 0) {
        free(ciphertext);
        return -EIO;
    }

    fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        free(ciphertext);
        return -errno;
    }

    printf("Writing to disk: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    res = pwrite(fd, ciphertext, ciphertext_len, offset);
    if (res == -1){
        perror("Write failed");
        res = -errno;
    } else if (res != ciphertext_len){
        fprintf(stderr, "Partial write. Expected %d, wrote %d\n", ciphertext_len, res);
        res = -EIO;
    }else{
        res = size;
    }

    close(fd);
    free(ciphertext);
    return res;
}

/**
 * @brief Reads the contents of a directory.
 * 
 * This function reads the contents of the directory at the given path and fills the provided buffer with directory entries. It first checks the access control list (ACL) permission to ensure that the current user has read permission for the directory. If the user does not have read permission, an access denied error (-EACCES) is returned.
 * 
 * The function uses the readdir system call to iterate over the directory entries and adds each entry to the buffer using the filler function. If the buffer is full and cannot accommodate more entries, an out of memory error (-ENOMEM) is returned.
 * 
 * @param path The path of the directory to read.
 * @param buf The buffer to fill with directory entries.
 * @param filler The function to add directory entries to the buffer.
 * @param offset The offset in the directory.
 * @param fi The file information.
 * @param flags Flags for readdir operation.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    (void) flags;

    if (!check_acl_permission(path, current_user, READ_PERMISSION)) {
        printf("user %s you dont have access to read from this directory", current_user);
        return -EACCES;
    }
    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        // Add directory entry to listing
        if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
            closedir(dp);
            return -ENOMEM;
        }
    }

    closedir(dp);
    return 0;
}


/**
 * @brief Creates a new file.
 * 
 * This function creates a new file with the specified path and mode. It first authenticates the current user before allowing the create operation. If the user authentication fails, an access denied error (-EACCES) is returned.
 * 
 * The function uses the creat system call to create the file with the specified path and mode. If the file creation fails, an error is returned. After creating the file, the function automatically sets full permissions for the creator by adding an ACL entry. If setting the ACL entry fails, the file is removed and an access denied error is returned.
 * 
 * @param path The path of the file to create.
 * @param mode The mode for the new file.
 * @param fi The file information.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {

    // Authenticate user before allowing create operation
    if (!authenticate_user(current_user, current_password)) {
        return -EACCES; // Access denied if authentication fails
    }

     // Create a new file with the specified path and mode
    int fd;
    (void) fi;

    // Open the file with the specified path and mode
    fd = creat(path, mode);
    if (fd == -1)
        return -errno;

    // Close the file descriptor
    close(fd);

    // Automatically set full permissions for the creator
    if (!add_acl_entry(path, current_user, READ_PERMISSION | WRITE_PERMISSION | EXECUTE_PERMISSION, ALLOW)) {
        fprintf(stderr, "Failed to set initial ACL for file %s\n", path);
        unlink(path);  // Remove the file if ACL setting fails
        return -EACCES; // Return an error if ACL entry could not be added
    }

    return 0; // Return success
}


/**
 * @brief Creates a new directory.
 * 
 * This function creates a new directory with the specified path and mode. It first authenticates the current user before allowing the mkdir operation. If the user authentication fails, an access denied error (-EACCES) is returned.
 * 
 * The function uses the mkdir system call to create the directory with the specified path and mode. If the directory creation fails, an error is returned. After creating the directory, the function automatically sets full permissions for the creator by adding an ACL entry. If setting the ACL entry fails, the directory is removed and an access denied error is returned.
 * 
 * @param path The path of the directory to create.
 * @param mode The mode for the new directory.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_mkdir(const char *path, mode_t mode) {
    // Authenticate user before allowing mkdir operation
    if (!authenticate_user(current_user, current_password)) {
        return -EACCES; // Access denied if authentication fails
    }

    // Create a new directory with the specified path and mode
    int res;
    
    // Use the mkdir system call to create a new directory with the specified path and mode
    res = mkdir(path, mode);
    if (res == -1){
        return -errno;
    }

    // Automatically set full permissions for the creator
    if (!add_acl_entry(path, current_user, READ_PERMISSION | WRITE_PERMISSION | EXECUTE_PERMISSION, ALLOW)) {
        fprintf(stderr, "Failed to set initial ACL for directory %s\n", path);
        rmdir(path);  // Remove the directory if setting ACL fails
        return -EACCES; // Return an error if ACL entry could not be added
    }

    printf("Directory created successfully with full permissions for %s\n", current_user);

    return 0; // Return success
}

/**
 * @brief Deletes a file.
 * 
 * This function deletes the file at the specified path. It first authenticates the current user before allowing the delete operation. If the user authentication fails, an access denied error (-EACCES) is returned.
 * 
 * The function checks the access control list (ACL) permission to ensure that the current user has write permission for the file. If the user does not have write permission, an access denied error (-EACCES) is returned.
 * 
 * The function uses the unlink system call to delete the file at the specified path. If the file deletion fails, an error is returned.
 * 
 * @param path The path of the file to delete.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_unlink(const char *path) {

       // Authenticate user before allowing delete operation
    if (!authenticate_user(current_user, current_password)) {
        return -EACCES; // Access denied if authentication fails
    }
    int res;

    if (!check_acl_permission(path, current_user, WRITE_PERMISSION)) {
        return -EACCES;
    }
    // Use the unlink system call to delete the file at the specified path
    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0; // Return success
}


/**
 * @brief Changes the size of a file.
 * 
 * This function changes the size of the file at the specified path. It uses the truncate system call to change the size of the file. If the truncate operation fails, an error is returned.
 * 
 * @param path The path of the file to truncate.
 * @param size The new size of the file.
 * @param fi The file information.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    int res;

    // Use the truncate system call to change the size of the file at the specified path
    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0; // Return success
}

/**
 * @brief Removes a directory.
 * 
 * This function removes the directory at the specified path. It first checks the access control list (ACL) permission to ensure that the current user has write permission for the directory. If the user does not have write permission, an access denied error (-EACCES) is returned.
 * 
 * The function uses the rmdir system call to remove the directory at the specified path. If the directory removal fails, an error is returned.
 * 
 * @param path The path of the directory to remove.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_rmdir(const char *path) {
    int res;

    // Use the rmdir system call to remove the directory at the specified path
    if (!check_acl_permission(path, current_user, WRITE_PERMISSION)) {
        return -EACCES;
    }

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0; // Return success
}

/**
 * @brief Renames a file or directory.
 * 
 * This function renames the file or directory at the old path to the new path. It first checks the access control list (ACL) permission to ensure that the current user has write permission for both the old path and the new path. If the user does not have write permission for either path, an access denied error (-EACCES) is returned.
 * 
 * The function uses the rename system call to perform the rename operation. If the rename operation fails, an error is returned.
 * 
 * @param oldpath The old path of the file or directory.
 * @param newpath The new path of the file or directory.
 * @param flags Flags for the rename operation.
 * @return On success, 0 is returned. On error, a negative value is returned.
 */
static int cfs_rename(const char *oldpath, const char *newpath, unsigned int flags) {

    // printf("function yet to be implemented");

    // Check permissions for oldpath and newpath
    if (!check_acl_permission(oldpath, current_user, WRITE_PERMISSION) || !check_acl_permission(newpath, current_user, WRITE_PERMISSION)) {
        return -EACCES;  // Access denied if the user doesn't have write permission on either path
    }

    int res = rename(oldpath, newpath);
    if (res == -1) {
        return -errno; // Return the error from errno if rename failed
    }

    return 0; // Success
}





int main(int argc, char *argv[]) {
    initialize_user_management();
    load_acls(ACL_FILENAME);

    if (strcmp(argv[1], "--debug-acl") == 0) {
    debug_show_access();
    return 0;
    }
    
    if (strcmp(argv[1], "--manage-acl") == 0) {
        char *path = NULL, *principal = NULL, *requestor = NULL;
        int permissions = 0, type = 0, action = 0;

        for (int i = 1; i < argc; i++) {
            if (strncmp(argv[i], "--path=", 7) == 0) {
                path = argv[i] + 7;
            } else if (strncmp(argv[i], "--principal=", 12) == 0) {
                principal = argv[i] + 12;
            } else if (strncmp(argv[i], "--requestor=", 12) == 0) {
                requestor = argv[i] + 12;
            } else if (strncmp(argv[i], "--permissions=", 14) == 0) {
                permissions = atoi(argv[i] + 14);
            } else if (strncmp(argv[i], "--type=", 7) == 0) {
                type = atoi(argv[i] + 7);
            } else if (strncmp(argv[i], "--action=", 9) == 0) {
                action = atoi(argv[i] + 9);
            }
        }

            char *password = get_current_password();
            if (user_exists(principal) && authenticate_user(principal, password)){
                // print_success("access granted you can now perfom action\n");
                manage_acl_entry(path, principal, requestor, permissions, type, action);
            } else {
                print_error("access denied you cannot perfom action\n");
            }
            return 0; // Exit after handling ACL management
        }
    
    char choice;
    printf("Welcome to the filesystem.\n");
    printf("Do you want to log in (L) or sign up (S)? ");
    scanf(" %c", &choice);
    clear_input_buffer();  // Clear the buffer after reading a single character

    switch (choice) {
        case 'L':
        case 'l': {
            // Log in
            int attempts = 3;
            int authenticated = 0;

            while (attempts > 0) {
                // Get current user's username and password
                char *username = get_current_user();
                char *password = get_current_password();

                // Check if user exists
                if (user_exists(username) && authenticate_user(username, password)){
                    print_success("Authentication successful\n");
                    authenticated = 1;

                    strncpy(current_user, username, MAX_USERNAME_LENGTH);
                    strncpy(current_password, password, MAX_PASSWORD_LENGTH);
                    break; // Exit loop if authentication successful
                } else {
                        print_error("Invalid credentials. %d attempts remaining.\n", attempts - 1);
                        printf(YEL "%d attempts remaining." RESET "\n", attempts - 1);
                        attempts--;
                }
            }
            if (!authenticated) {
                print_error("Authentication failed. Exiting...\n");
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'S':
        case 's': {
            // Sign up
            printf("\n");
            char *username = get_current_user();
            char *password = get_current_password();
            clear_input_buffer();  // Clear the buffer after reading a single character

            if (create_user(username, password)) {
                print_success("New user account created successfully\n");
            } else {
                print_error("Failed to create user account\n");
                exit(EXIT_FAILURE);
            }

            break;
        }

        default:
            print_error("Invalid choice. Exiting...\n");
            exit(EXIT_FAILURE);
    }
    return fuse_main(argc, argv, &cfs_oper, NULL);
}