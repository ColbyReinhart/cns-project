# A python implementation of SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 4-14-2022

from cmath import log

# GLOBAL CONSTANTS
b = 256 # size of message digest/state array
w = b / 25
l = log(w, 2)

# STEP MAPPING SPECIFICATIONS
# The five step mappings that comprise a round are θ, ρ, π, χ, ι

# Specification of Algorithm 1: θ(A)
# Input: state array A, which is a 3-dimensional array
# Output: state array A'
def theta(A):
	# For all pairs (x,z) such that 0 <= x <= 5 and 0 <= z <= w, let
	# C[x,z]=A[x,0,z] ⊕ A[x,1,z] ⊕ A[x,2,z] ⊕ A[x,3,z] ⊕ A[x,4,z]
	C = []
	for x in range(5):
		C.append([])
		for z in range(w):
			result = A[x,0,z] ^ A[x,1,z] ^ A[x,2,z] ^ A[x,3,z] ^ A[x,4,z]
			C[x].append(result)
			
	# For all pairs (x, z) such that 0≤x<5 and 0≤z<w let 
	# D[x,z]=C[(x - 1) mod 5, z] ⊕ C[(x + 1) mod 5, (z – 1) mod w]
	D = []
	for x in range(5):
		D.append([])
		for z in range(w):
			result = C[(x - 1) % 5, z] ^ C[(x + 1) % 5, (z - 1) % w]
			D[x].append(result)
			
	# For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
	# A′[x, y,z] = A[x, y,z] ⊕ D[x,z]
	Aprime = []
	for x in range(5):
		Aprime.append([])
		for y in range(5):
			Aprime[x].append([])
			for z in range(w):
				Aprime[x][y].append(A[x][y][z] ^ D[x][z])
	
	return Aprime
