#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	FILE *fp;
	FILE *fpa;
	char buffer[1000];
	char buffera[1000];
	int i;
	int a;
	int b;
	int match=0;
	int total=0;
	fp = fopen(argv[1], "r");
	fpa = fopen(argv[2], "r");
	for(i=0 ; i < 1000 ; i++){
		buffer[i] = 0;
		buffera[i] = 0;
	}
	while(fgets(buffer, sizeof(buffer), fp)){
		fgets(buffera, sizeof(buffera), fpa);
		a = atoi(buffer);
		b = atoi(buffera);
		if((a == 0) || (b == 0)){
			total--;
		}
		if(a==b){
			match++;
		}
		total++;
		for(i=0 ; i < 1000 ; i++){
			buffer[i] = 0;
			buffera[i] = 0;
		}
	}
	printf("%f\n", (double)match/(double)total);
}
