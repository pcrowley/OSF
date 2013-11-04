#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	FILE *fp;
	char b[1000];
	int i;
	for(i=0 ; i<1000 ; i++){
		b[i] = 0;
	}
	fp = fopen(argv[1], "r");
	while(fgets(b, sizeof(b), fp)){
		if(atoi(b) != 0){
			printf("%s", b);
		}
		for(i=0 ; i < 1000 ; i++){
			b[i] = 0;
		}
	}
}
