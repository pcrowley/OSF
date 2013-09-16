#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include "svm.h"
#include "fnv.h"
#include "pna_hashmap.h"

int main(int argc, char **argv){
	struct svm_model *model;
	model = svm_load_model(argv[1]);
	printf("%f %f\n", model->param.gamma, model->param.C);
	return 0;
}
