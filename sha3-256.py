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

