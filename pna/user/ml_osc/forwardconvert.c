#include <stdio.h>

int main(int argc, char **argv){
	FILE *fp;
	FILE *fpa;
	char table[1000][1000];
	char buffer[1000];
	int i,j,k,l;
	int size=0;
	fp = fopen(argv[1], "r");
	for(i=0 ; i < 1000 ; i++){
		table[0][i] = 0;
	}
	while(fgets(table[size], sizeof(table[size]), fp)){
		size++;
		for(i=0 ; i < 1000 ; i++){
			table[size][i] = 0;
		}
	}
	fclose(fp);
	fp = fopen(argv[2], "r");
	for(i=0  ; i < 1000 ; i++){
		buffer[i] = 0;
	}
	while(fgets(buffer, sizeof(buffer), fp)){
		for(i=0 ; i < size ; i++){
			for(j=0 ; j < 1000 ; j++){
				if(buffer[j] != table[i][j]){
					break;
				}
			}
			if(j == 1000){
				printf("%d\n", i);
				break;
			}
		}
		if(i == size){
			printf("0\n");
		}
		for(i=0 ; i < 1000 ; i++){
			buffer[i] = 0;
		}
	}
}
