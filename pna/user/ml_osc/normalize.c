#include <stdio.h>
#include <stdlib.h>

void convert_features(char buffer[1000], int features[61]){
	int i;
	char *temp;
	for(i=0 ; i < 61 ; i++){
		features[i] = 0;
	}
	for(i=0 ; i < 1000 ; i++){
		if(buffer[i] == ','){
			buffer[i] = '\n';
		}
	}
	i=0;
	temp = buffer;
	while(i < 61){
		features[i++] = atoi(temp);
		if(i == 61){
			break;
		}
		while(*temp != '\n'){
			temp++;
		}
		temp++;
	}
	for(i=0 ; i < 61 ; i++){
		//printf("%d ", features[i]);
	}
	//printf("\n");
}

int main(int argc, char **argv){
	FILE *fp;
	char buffer[1000];
	int i, j;
	int feat_size=0;
	int test_size=0;
	int features[20000][61];
	int ranges[61];
	fp = fopen(argv[1], "r");
	for(i=0 ; i < 1000 ; i++){
		buffer[i] = 0;
	}
	while(fgets(buffer, sizeof(buffer), fp)){
		convert_features(buffer, features[feat_size++]);
		for(i=0 ; i < 1000 ; i++){
			buffer[i] = 0;
		}
	}
	fclose(fp);
	fp = fopen(argv[2], "r");
	for(i=0 ; i < 1000 ; i++){
		buffer[i] = 0;
	}
	test_size=0;
	while(fgets(buffer, sizeof(buffer), fp)){
		ranges[test_size++] = atoi(buffer);
		for(i=0 ; i < 1000 ; i++){
			buffer[i] = 0;
		}
	}
	for(i=0 ; i < feat_size ; i++){
		for(j=0 ; j < 61 ; j++){
			printf("%f", (double)features[i][j]/(double)ranges[j]);
			if(j < 60){
				printf(",");
			}
			else{
				printf("\n");
			}
		}
	}
}
