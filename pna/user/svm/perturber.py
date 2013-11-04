import sys
import random
g = open(sys.argv[1], "r")
ranges = []
for line in g:
	ranges.append(int(line))
pert_index = int(sys.argv[3])
f = open(sys.argv[2], "r")
for line in f:
	temp = line.split(',')
	for a in range(len(temp)):
		if(a == pert_index):
			if(pert_index == 13):
				over = random.randint(0, ranges[pert_index])
				sys.stdout.write(str(over))
			else:
				sys.stdout.write(str(random.randint(0, ranges[pert_index])))
		elif(a == 13 and pert_index == 60):
			sys.stdout.write("0")
		elif(a == 60 and pert_index == 13):
			if(int(temp[56]) == 0):
				sys.stdout.write("0")
			elif((over % int(temp[56])) == 0):
				sys.stdout.write(str(over / int(temp[56])))
			else:
				sys.stdout.write("0")
		else:
			sys.stdout.write(str(int(temp[a])))
		if(a != len(temp)-1):
			sys.stdout.write(',')
	sys.stdout.write('\n')
