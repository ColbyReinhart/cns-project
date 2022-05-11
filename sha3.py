# A python implementation of SHA3-256
# Colby Reinhart
# CS-45203: Computer Network Security
# 5-10-2022

# USAGE:
# Requires python 3.10.0 or higher
# Execute with "python sha3-256-v2.py"
# TODO: ADD EXECUTION INSTRUCTIONS

# KECCAK CONSTANTS
l = 6		# Important for other constants/calculations
w = 2 ** l	# The size of the z-axis in the state; how "long" the state is (64)
b = 25 * w	# The amount of bits in the state; the "width" of the state array (1600)
r = 1088	# The block size, or the size of each stream block
c = b - r	# The capacity, which is padded to r for the keccak function (512)

# General constants
digestSize = 256
numRounds = 12 + (2 * l)    # The number of rounds for each f-function (24)
RC = [
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000001000000010000010",
		"1000000000000000000000000000000000000000000000001000000010001010",
		"1000000000000000000000000000000010000000000000001000000000000000",
		"0000000000000000000000000000000000000000000000001000000010001011",
		"0000000000000000000000000000000010000000000000000000000000000001",
		"1000000000000000000000000000000010000000000000001000000010000001",
		"1000000000000000000000000000000000000000000000001000000000001001",
		"0000000000000000000000000000000000000000000000000000000010001010",
		"0000000000000000000000000000000000000000000000000000000010001000",
		"0000000000000000000000000000000010000000000000001000000000001001",
		"0000000000000000000000000000000010000000000000000000000000001010",
		"0000000000000000000000000000000010000000000000001000000010001011",
		"1000000000000000000000000000000000000000000000000000000010001011",
		"1000000000000000000000000000000000000000000000001000000010001001",
		"1000000000000000000000000000000000000000000000001000000000000011",
		"1000000000000000000000000000000000000000000000001000000000000010",
		"1000000000000000000000000000000000000000000000000000000010000000",
		"0000000000000000000000000000000000000000000000001000000000001010",
		"1000000000000000000000000000000010000000000000000000000000001010",
		"1000000000000000000000000000000010000000000000001000000010000001",
		"1000000000000000000000000000000000000000000000001000000010000000",
		"0000000000000000000000000000000010000000000000000000000000000001",
		"1000000000000000000000000000000010000000000000001000000000001000"
	]

# STEPS
# 1) Take an input string
# 2) Split it into blocks of r bits, with the last block being padded
#      a) While we have more than r bits remaining in the message, make a block of r
#      b) Pad the last block with a 1, then 0's then a 1 to make its length = r
# 3) Create an initial state of size b with all 0's
# 4) For each block of r bits created from the message:
#      a) XOR the first r bits of the state with the block
#      b) Put the state with the XORed rate into the f-function (24 rounds of Keccak)
#      c) Feed the output into the next iteration
# 5) Take the first 256 bits of the resulting state. This is the final output

#
# PREPROCESSING FUNCTIONS
#

# Convert an input string of arbitrary length int a string of bits
# Input: a text string of any length
# Output: a bit string representing the text in binary
# The result is such that each 8 bits is the reversed version of an ASCII code
def stringToBits(textString):
	result = []
	for character in textString:
		letterCode = ord(character)			# Get the ASCII code
		byte = '{0:08b}'.format(letterCode)	# Convert ASCII to binary
		byte = byte[::-1]					# Convert to little endian form
		byte = [int(c) for c in byte]		# Convert into a list of bits
		result.extend(byte)					# Append the list onto result
	return result

# Implementation of pad10*1
# Pads a string with a 1, then 1 or more 0's, then a 1 to be of length
# Input: padded length to achieve x, length of current string m
# Output: A padding which when appended to a string of size m creates a string size x
def pad10_1(x, m):
	j = (-m - 2) % x				# Get necessary remaining 0's
	result = [1]					# result = 1
	result.extend([0] * j)			# result = 1, 0^j
	result.append(1)				# result = 1, 0^j, 1
	return result

# Convert a bit string into a state array
# Input: bit string S
# Output: state array representing S
def bitsToStateArray(S):
	stateArray = []
	for x in range(5):
		stateArray.append([])
		for y in range(5):
			stateArray[x].append([])
			for z in range(w):
				stateArray[x][y].append(S[w * (5 * y + x) + z])
	return stateArray

# Convert a state array back into a bit string
# Input: state array S
# Output: the bit string representing S
def stateArrayToBits(S):
	# Construct lanes
	laneList = []
	for j in range(5):
		for i in range(5):
			laneList.append(S[i][j])
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


#
# KECCAK FUNCTIONS
#

# theta implementation
# Input: state array S
# Input: altered state array S'
def theta(S):
	C = []
	for x in range(5):
		C.append([])
		for z in range(w):
			C[x].append(0)
			for y in range(5):
				C[x][z] ^= S[x][y][z]
	
	D = []
	for x in range(5):
		D.append([])
		for z in range(w):
			D[x].append(C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % w])

	for x in range(5):
		for y in range(5):
			for z in range(w):
				S[x][y][z] ^= D[x][z]
	return S

# rho implementation
# Input: state array S
# Input: altered state array S'
def rho(S):
	x = 1
	y = 0
	for t in range(24):
		for z in range(w):
			S[x][y][z] = S[x][y][int(z - (t + 1) * (t + 2) // 2) % w]
			xTemp = x
			yTemp = y
			x = yTemp
			y = ((2 * xTemp) + (3 * yTemp)) % 5
	return S

# pi implementation
# Input: state array S
# Output: altered state array S'
def pi(S):
	for x in range(5):
		for y in range(5):
			for z in range(w):
				S[x][y][z] = S[(x + (3 * y)) % 5][x][z]
	return S

# chi implementation
# Input: state array S
# Output: altered state array S'
def chi(S):
	for x in range(5):
		for y in range(5):
			for z in range(w):
				S[x][y][z] ^= ((S[(x + 1) % 5][y][z] ^ 1) * (S[(x + 2) % 5][y][z]))
	return S

# iota implementation
# Input: state array S, round number roundNumber
# Output: altered state array S'
def iota(S, roundNumber):
	roundConstant = [int(bit) for bit in RC[roundNumber]]
	for z in range(w):
		S[0][0][z] ^= roundConstant[z]
	return S

# Implemention of one permutation of KECCAK-p
# Input: state array S
# Output: state array S' which has gone through 12 + 2l rounds of KECCAK-p
def keccakP(S):
	stateArray = bitsToStateArray(S)
	for roundIndex in range(numRounds):
		stateArray = iota(chi(pi(rho(theta(stateArray)))), roundIndex)
	return stateArrayToBits(stateArray)

#
# RUN SHA3
#

def sha3_256(input):

	# Convert input to bit string
	bitString = stringToBits(input)

	# Add '01' to the end (per specification)
	bitString.extend([0, 1])

	# Split the bit string into blocks of length r
	blocks = []
	while len(bitString) > r:
		blocks.append(bitString[:r])
		bitString = bitString[r:]
	
	# Pad the last block to be length r
	bitString.extend(pad10_1(r, len(bitString)))
	blocks.append(bitString)

	# Create the initial state
	state = [0] * b

	# Run sponge construction on each block
	for block in blocks:

		# XOR the block with the first r bits of the state
		for i in range(r):
			state[i] ^= block[i]

		# Run the state through the f-function
		state = keccakP(state)

	# Get the first digestSize bits from the resulting state
	digest = state[:digestSize]

	# Convert each byte back to big endian
	flippedDigest = []
	for i in range(0, digestSize, 8):
		temp = digest[i:i+8]
		temp = temp[::-1]
		flippedDigest.extend(temp)
	digest = flippedDigest

	# Convert from a bit list to a hex string
	digest = hex(int("".join([str(bit) for bit in digest]), 2))
	digest = digest[2:]	# Remove the "0x" which gets added by hex()
	
	# Return the result
	return digest

result = sha3_256(input("Give some input: "))
print(result)