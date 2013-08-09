#include <stdio.h>
#include <stdlib.h>
#include "randomForest.h"

int tree_classify(struct tree_node *tree, int num_nodes, unsigned int *features, unsigned int num_features){
	int i=0;
	while(tree[i].done != -1){
		if(features[tree[i].attr] <= tree[i].value){
			i = tree[i].true_index;
		}
		else{
			i = tree[i].false_index;
		}
	}
	return tree[i].result;
}

struct forest_result rf_classify(struct tree_node **forest, int num_trees, int *num_nodes, int max_class, unsigned int *features, unsigned int num_features){
	int *votes;
	int i;
	int result;
	int max=0;
	int max_index=-1;
	int total=0;
	struct forest_result ret;
	votes = (int *)malloc(sizeof(int)*(max_class+1));
	for(i=0 ; i < max_class+1 ; i++){
		votes[i] = 0;
	}
	for(i=0 ; i < num_trees ; i++){
		result = tree_classify(forest[i], num_nodes[i], features, num_features);
		votes[result]++;
		if(votes[result] > max){
			max = votes[result];
			max_index = result;
		}
	}
	ret.result = max_index;
	ret.percent = (double)max/(double)num_trees;
	return ret;
}
