#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){
	FILE *fpa;
	FILE *fpb;
	char b1[1000];
	char b2[1000];
	int i;
	fpa = fopen(argv[1], "r");
	fpb = fopen(argv[2], "r");
	for(i=0 ; i < 1000 ; i++){
		b1[i] = 0;
		b2[i] = 0;
	}
	while(fgets(b1, sizeof(b1), fpa)){
		fgets(b2, sizeof(b2), fpb);
		if(atoi(b2) != 0){
			printf("%s", b1);
		}
		for(i=0 ; i < 1000 ; i++){
			b1[i] = 0;
			b2[i] = 0;
		}
	}
}
