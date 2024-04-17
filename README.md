# Cryptographic File System (CFS)

## Overview

Cryptographic File System (CFS) is a user-space file system based on FUSE (Filesystem in Userspace) that provides encrypted storage and access control mechanisms. This project uses AES encryption to protect file contents and implements Access Control Lists (ACL) for file and directory permissions management.

## Prerequisites

- Linux environment (Ubuntu or any other distros)
- sudo or root access

## Installation

1. **Prepare the Environment:**
   Ensure you are operating in a Linux environment. This setup requires permissions to install packages and make system changes.

2. **Unzip the Project:**
   Extract the provided zip file which contains the FUSE library source and the `src` directory of the Cryptographic File System.

3. **Setup Dependencies:**
   Navigate to the project directory where the `Makefile` is located and run:
   ```bash
   make setup_fuse
   ```

This command will install necessary packages, compile, and install the FUSE library. Enter your password when prompted for sudo commands.

1. **Configure Paths:**
    - Navigate to the src directory.
    - Create two files: user_accounts.txt and file_permissions.txt.
    - Copy the absolute path of file_permissions.txt and replace the placeholder in acl.h:
    ```c
    #define ACL_FILENAME "/absolute/path/to/file_permissions.txt"
    ```
    - Replace the path in user_management.h line 159 with the absolute path to the src directory:
    ```c
    #define USER_DIRECTORY "/absolute/path/to/src"
    ```

2. **Compile the File System:**
From the project root directory (one level up from src), run:
```bash
make
```
This will compile the cryptographic file system.

3. **Mount the File System:**
Navigate back to the src directory and run:
```bash
./cfs -d mountpoint
```
This command mounts the filesystem to the mountpoint directory and starts it in debug mode. Follow the prompts to sign up or log in.

## Usage

Once the file system is mounted, you can interact with it using common Unix commands prefixed with mountpoint/, such as:

``` bash
cd mountpoint/somedir
ls mountpoint/somedir
mkdir mountpoint/dirname
touch "some message" > mountpoint/somedir
rm mountpoint/somedir/somefilename
mv mountpoint/somedir/somefilename mountpoint/otherdir
cat mountpoint/somedir/somefilename
```
These commands will interact with files and directories under the encrypted file system.

## Managing Access Control Lists (ACL)
To specify access levels for directories for specific users, use:
``` bash
./cfs --manage-acl --path=directory_path --principal=user --requestor=requesting_user --permissions=permission_level --type=allow_or_deny --action=add_or_remove
```

- Example Command:
``` bash
./cfs --manage-acl --path=john/docs --principal=jane --requestor=john --permissions=7 --type=1 --action=0
```
To debug or list ACL settings:
``` bash
./cfs --debug-acl
```

## Using Midnight Commander
For easier navigation and file management, run:
``` bash
mc /path/to/mountpoint
```

## Unmounting
To unmount the filesystem when you're done, use:
``` bash
fusermount -u mountpoint
```

OR

``` bash
sudo umount -l mountpoint
```
Ensure you are in the directory above mountpoint when running this command (ideally, ```src``` directory).

## Authors & Contributors
```
Aaron Tsatsu Tamakloe (Github: @aarontsatsu), John Terence Manful (Github: @jt-manful)
```

## Project Youtube Link
<https://www.youtube.com/watch?v=sTNkW7d2ZVo>
