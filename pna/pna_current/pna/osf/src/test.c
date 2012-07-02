#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>



#define DEFAULT_LOG_DIR  "./logs"
#define DEFAULT_INTERVAL 10
#define LOG_FILE_FORMAT  "%s/pna-%%Y%%m%%d%%H%%M%%S-%s.log"
#define MAX_STR          1024
#define BUF_SIZE         (1 * 1024 * 1024)
#define USECS_PER_SEC    1000000


struct osf_print{
	int done;
	char a;
	char b;
	char c;
};

int main(int argc, char **argv){
	int fd;
	int size;
	struct stat pf_stat;
	struct osf_print *tester;
	    /* fetch size of proc file (used for mmap) */
    if (stat("/proc/osf_log", &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;
    fd = open("/proc/osf_log", O_RDONLY);
	        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
            }
            perror("open proc_file");
            return -1;
        }
	tester = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	        if (tester == MAP_FAILED) {
            perror("mmap");
            close(fd);
        }
	printf("%c %c %c\n", tester->a, tester->b, tester->c);
	close(fd);
	return 0;
}
