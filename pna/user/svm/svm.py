import numpy as np
import mlpy

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

C_val = [1000.0]
gamma_val = [1e-6]

max_val = 0.0
max_gamma = 0.0
max_C = 0.0

iters = 0
total_iters = len(C_val) * len(gamma_val)
#print "In svm.py"

for c in C_val:
	for g in gamma_val:
		iters = iters + 1
		svm = mlpy.LibSvm(svm_type='c_svc', kernel_type='rbf', gamma = g, C = c)
		svm.learn(x,y)
		p = svm.pred(z)
		#for a in p:
			#print int(a)
		temp = match(p,t)
		print temp
		if(temp > max_val):
			max_val = temp
			max_gamma = g
			max_C = c
#print "Max Vals, gamma, C"
#print max_val
#print max_gamma
#print max_C

svm.save_model("svm.model")
