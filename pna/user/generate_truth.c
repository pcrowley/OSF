#include <stdio.h>
#include <string.h>

#define MAX 1000000

unsigned int classified[MAX];
char buffer[MAX][1000];
unsigned int result[MAX];
unsigned int total_lines;

void classify(char *string, unsigned int class, int index){
	int i;
	result[index] = class;
	classified[index] = 1;
	for(i=0 ; i < total_lines ; i++){
		if(classified[i] == 1){
			continue;
		}
		if(strcmp(string, buffer[i]) == 0){
			classified[i] = 1;
			result[i] = class;
		}
	}
	return;
}

int main(int argc, char **argv){
	FILE *fp;
	int i;
	unsigned int class = 1;
	total_lines = 0;
	if(argc != 2){
		printf("args\n");
		return 0;
	}
	fp = fopen(argv[1], "r");
	if(fp == NULL){
		printf("file open\n");
		return 0;
	}
	while(fgets(buffer[total_lines], 1000, fp)!=NULL){
		total_lines++;
	}
	fclose(fp);
	for(i=0 ; i < total_lines ; i++){
		result[i] = 0;
		classified[i] = 0;
	}
	for(i=0 ; i < total_lines ; i++){
		if(classified[i] == 0){
			classify(buffer[i], class, i);
			class++;
		}
	}
	printf("%u\n", total_lines);
	for(i=0 ; i < total_lines ; i++){
		printf("%u\n", result[i]);
	}
	return 0;
}
