#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	FILE *fpa;
	FILE *fpb;
	char ba[2000];
	char bb[2000];
	int i,j,k;
	fpa = fopen(argv[1], "r");
	fpb = fopen(argv[2], "r");
	for(i=0 ; i < 2000 ; i++){
		ba[i] = 0;
		bb[i] = 0;
	}
	while(fgets(ba, sizeof(ba), fpa)){
		fgets(bb, sizeof(bb), fpb);
		j = atoi(ba);
		printf("%d,%s", j, bb);
		for(i=0 ; i < 2000 ; i++){
			ba[i] = 0;
			bb[i] = 0;
		}
	}
	return 0;

}
