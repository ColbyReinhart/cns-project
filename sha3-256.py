# A python implementation of SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 4-14-2022

from distutils.log import error
import sys
import argparse

# GLOBAL HARD-CODED CONSTANTS FOR KECCAK
l = 6		# Change this as desired from {0,1,2,3,4,5,6}
w = 2 ** l	# The width of the z-index of the state array
b = 25 * w	# 5 * 5 * w, the width of the entire state array (1600)

# GLOBAL HARD-CODED CONSTANTS FOR SPONGE CONSTRUCTION
outbits = 256			# The size of the message digest
capacity = 2 * outbits	# capacity of the sponge function (512)
rate = b - capacity		# rate of the sponge function (1088)

# Convert in input character string into bits
def stringToBits(input):
	result = []
	for char in input:
		letterCode = ord(char)				# get the letter code
		byte = '{0:08b}'.format(letterCode)	# convert to binary
		byte = byte[::-1]					# reverse, convert to little endian
		byte = [int(c) for c in byte]		# Convert into list of bits
		result.extend(byte)					# Append the list onto result
	return result

# Convert a bitstring into a string of characters
# Assumes the provided bit string % 8 == 0
def bitsToString(input):
	result = ''
	for i in range(len(input) // 8):
		value = 0

		# Convert byte to int
		for j in range(8):
			if input[(8 * i) + j] == 1:
				value += (2 ** j)
		
		# Convert int to char and append to string
		result += chr(value)

	return result

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

# Convert a state array back into a bitstring
def stateArrayToBits(input):
	# Construct lanes
	laneList = []
	for j in range(5):
		for i in range(5):
			laneList.append(input[i][j])
	# laneList: (0,0), (1,0), (2,0) ... (0,1), (1,1), (2,1) ... etc

	#Construct planes
	planeList = []
	counter = 0
	for i in range(5):
		planeList.append([])
		for j in range(5):
			planeList[i].extend(laneList[counter])
			counter += 1

	# Construct final list
	bitstring = []
	for plane in planeList:
		bitstring.extend(plane)

	# Return the resulting bitstring
	return bitstring

# STEP MAPPINGS

# theta implementation
# Takes in a state array A and value w (globally defined)
# Returns A', which is the state array with each bit XORed with the parities
# of two columns in the array
def theta(state_array):
	# Define C and D, which will be temporary containers
	C = []
	
	# Fill C with XORs from each column of the state
	for x in range(5):
		C.append([])
		for z in range(w):
			C[x].append(0)
			for y in range(5):
				C[x][z] ^= state_array[x][y][z]

	# Fill D with operations based on C
	D = []
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
			result[x][y][z] = state_array[x][y][int((z - (t + 1) * (t + 2) / 2) % w)]
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

# KECCAK-p[b, nr]
# Inputs: bitstring S, number of rounds nr
# Output: bitstring S' of length b
def keccakP(inputString, numberOfRounds):
	state_array = bitsToStateArray(inputString)
	begin = 12 + (2 * l) - numberOfRounds
	end = 12 + (2 * l) - 1
	for i in range(begin, end + 1):
		state_array = iota(chi(pi(rho(theta(state_array)))), i)
	return state_array

# SPONGE CONSTRUCTION

# pad10*1 implementation
# Input: positive integer x, non-negative integer m
# Output: string P such that m + len(P) is a positive multiple of X
def pad(x, m):
	j = (0 - m - 2) % x
	result = [1]
	for i in range(j):
		result.append(0)
	result.append(1)
	return result

# sponge implementation
# Inputs: bitstring N, nonnegative integer d
# Output: String Z such that len(Z) = d
def sponge(N, numRounds):
	# Copy N into P
	P = []
	for i in range(len(N)):
		P.append(N[i])

	# Pad P with 0's to equal 1600 bits
	P.extend([0] * 512)

	# Build initial value (1600 bits)
	state = [0] * (b)

	# XOR with state and perform keccak
	for i in range(numRounds):
		
		# Get a block and pad it with zeroes to make it 1600 bits long
		block = P[(i * rate):(i * rate) + rate]	
		block.extend([0] * capacity)

		# XOR state with block
		xorResult = [lhs ^ rhs for lhs, rhs in zip(state, block)]

		# Run result through f, which is keccak
		state = keccakP(xorResult, 12 + (2 * l))

		# Convert result back into bit string
		state = stateArrayToBits(state)
	
	# Return the first 256 bits of the resulting array, which is the hash
	return state[:256]

## RUN SHA3-256
message = input("Please enter a message to hash:\n")	# Get input
shaInput = stringToBits(message)						# Char string -> list of bits
shaInput.extend([0, 1, 1, 0, 0, 0, 0, 0])				# Add SHA3 suffix
shaInput += pad(rate, len(shaInput) % rate)				# Pad bit list to % 1088 bits
result = sponge(shaInput, len(shaInput) // rate)		# Run SHA3-256

# Convert the result into the correct form
hash = ""
for i in range(32):
	# Get a byte
	byte = ""
	for j in range(8):
		byte += str(result[(i * 8) + j])

	# Convert to big-endian
	byte = byte[::-1]

	# Format
	hash += '{0:02x}'.format(int(byte, 2))

print("Result:\n" + hash)