#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(int argc, char **argv){
	double a, b;
	int ret;
	if(argc != 3){
		printf("1");
		return -1;	
	}
	a = atof(argv[1]);
	b = atof(argv[2]);
	a = (a / 100.0);
	ret = (int)(a * b);
	if(ret > (int)b){
		ret = (int)b;
	}
	if(ret < 1){
		ret = 1;
	}
	printf("%d", ret);
	return 0;
}
