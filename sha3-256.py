# A python implementation of SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 4-14-2022

import sys
import numpy
import argparse

# GLOBAL HARD-CODED CONSTANTS FOR KECCAK
l = 6		# Change this as desired from {0,1,2,3,4,5,6}
w = 2 ** l	# The width of the z-index of the state array
b = 25 * w	# 5 * 5 * w, the width of the entire state array

# Convert in input character string into bits
def stringToBits(input):
	result = ''
	for char in input:
		letterCode = ord(char)				# get the letter code
		byte = '{0:08b}'.format(letterCode)	# convert to binary
		byte = byte[::-1]					# reverse, convert to little endian
		result += byte						# add byte to the result
	result += '01100000' # Denote SHA3 with appropriate suffix

# Convert a bitstring into a 5*5*w state array
def bitsToStateArray(input):
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				value = (w * ((5 * y) + x) + z)				# generate value ///
				if (value < b):								# Index the string
					result[x][y].append(int(input[value]))	# Fill in the state
	return result

# STEP MAPPINGS

# theta implementation
# Takes in a state array A and value w (globally defined)
# Returns A', which is the state array with each bit XORed with the parities
# of two columns in the array
def theta(state_array):
	# Define C and D, which will be temporary containers
	C, D = []
	
	# Fill C with XORs from each column of the state
	for x in range(5):
		C.append([])
		for z in range(w):
			C[x].append(0)
			for y in range(5):
				C[x][z] ^= state_array[x, y, z]

	# Fill D with operations based on C
	for x in range(5):
		D.append([])
		for z in range(w):
			D[x].append(C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % w])
	
	# Fill in A' based on A and D
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				result[x][y].append(state_array[x][y][z] ^ D[x][z])
	
	# Return A'
	return result

# rho implementation
# Takes in a state array A and value w (globally defined)
# Returns A', which is the state array with each bit rotated
def rho(state_array):
	# Initialize A' and match z at x and y = 0
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				result[x][y].append(0)
	
	for z in range(w):
		result[0][0][z] = state_array[0][0][z]
	
	#Initialize x and y for later use
	x = 1
	y = 0

	# Perform circular shift
	for t in range(24):
		for z in range(w):
			result[x][y][z] = state_array[x][y][(z - (t + 1) * (t + 2) / 2) % w]
			tempX = x
			tempY = y
			x = y
			y = ((2 * tempX) + (3 * tempY)) % 5

	# Return A'
	return result

# pi implementation
# Takes in a state array A and value w (globally defined)
# Returns A', which is the state array with each slice linearly transformed
def pi(state_array):
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				result[x][y].append(state_array[(x + (3 * y)) % 5][x][z])
	return result

# chi implementation
# Takes in a state array A and value w (globally defined)
# Returns A', which is the state array with each bit XORed with a non-linear
# function of two other bits in its row
def chi(state_array):
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				temp1 = state_array[(x + 1) % 5][y][z] ^ 1
				temp2 = state_array[(x + 2) % 5][y][z]
				result[x][y].append((state_array[x][y][z] ^ temp1) * temp2)
	return result

# rc implementation
# Takes in an integer t
# Returns a bit servins as a round constant
def rc(t):
	if t % 255 == 0:
		return 1

	R = [1,0,0,0,0,0,0,0]
	for i in range (1, (t % 255) + 1):
		R.insert(0, 0)	# Insert a 0 at the front
		R[0] ^= R[8]
		R[4] ^= R[8]
		R[5] ^= R[8]
		R[6] ^= R[8]
		R.pop()
	
	return R[0]

# iota implementation
# Takes in a state array A, a value w (globally defined), and a round index ir
# Returns A', which is the state array with modifications depending on the
# round index
def iota(state_array, round_index):
	# Copy A into A'
	result = []
	for x in range(5):
		result.append([])
		for y in range(5):
			result[x].append([])
			for z in range(w):
				result[x][y].append(state_array[x][y][z])
	
	# Define RC, which is a string of w zeroes
	RC = []
	for i in range(w):
		RC.append(0)

	# STEP 3
	for j in range(l + 1):
		RC[2 ** j - 1] = rc(j + (7 * round_index))

	# STEP 4
	for z in range(w):
		result[0][0][z] ^= RC[z]

	return result

