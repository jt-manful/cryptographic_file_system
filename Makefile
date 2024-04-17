CC = gcc
# Use pkg-config to get FUSE3 compilation flags and link flags
CFLAGS = $(shell pkg-config --cflags fuse3) -D_FILE_OFFSET_BITS=64
LDFLAGS = $(shell pkg-config --libs fuse3) -lpthread -lssl -lcrypto

SRC = src/cfs.c
OBJ = $(SRC:.c=.o)
EXEC = src/cfs

# The default target
all: setup_fuse $(EXEC) post-setup

# Builds the executable
$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Compiles the object files
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Set up FUSE from the pre-existing archive
setup_fuse:
	@echo "Unzipping FUSE..."
	tar -xzf fuse-3.16.2.tar.gz
	cd fuse-3.16.2 && meson setup build
	@echo "Building FUSE..."
	cd fuse-3.16.2/build && ninja
	@echo "Installing FUSE..."
	cd fuse-3.16.2/build && sudo ninja install
	sudo ldconfig
	fusermount3 -V
	sudo apt install mc

post-setup:
	@echo "Creating directories and initializing files..."
	mkdir -p src/mountpoint

# Cleans build artifacts and other created directories and files
clean:
	@echo "Cleaning up build artifacts and dependencies..."
	rm -f $(OBJ) $(EXEC)
	rm -rf src/mountpoint
	rm src/user_accounts.txt src/file_permissions.txt
	rm -rf fuse-3.16.2

