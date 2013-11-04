import numpy as np
import mlpy
import datetime

def match(a,b):
	total=0
	less_val=0
	for i in range(len(a)):
		c = a[i]
		d = b[i]
		if(c == 0 or d == 0):
			less_val = less_val + 1
		if(int(c) == int(d)):
			total = total + 1
	return (float(total) / float(len(a)-less_val))

x = np.loadtxt("svm_data.txt", delimiter=',')
y = np.loadtxt("svm_truth.txt")
z = np.loadtxt("svm_data_test.txt", delimiter=',')
t = np.loadtxt("svm_truth_test.txt")

svm = mlpy.LibSvm.load_model("svm.model")

print datetime.datetime.now()
for a in range(10):
	p = svm.pred(z)
print datetime.datetime.now()
