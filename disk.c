#define DISK_BLOCK_SIZE 4096 //Just like a real disk, the emulator only allows operations on entire disk blocks of 4 KB 


static FILE *diskfile;
static int nblocks=0;
static int nreads=0;
static int nwrites=0;



// initialize disk
disk_init(const char *imageFile, int fileSize ){

    diskfile = fopen(imageFile,"r+");
	if(!diskfile) diskfile = fopen(filimageFileename,"w+");
	if(!diskfile) return 0;

	ftruncate(fileno(diskfile),n*DISK_BLOCK_SIZE);

	nblocks = n;
	nreads = 0;
	nwrites = 0;

	return 1;

}