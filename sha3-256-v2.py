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
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
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

#
# RUN SHA3
#

def sha3_256(input):

	# Convert input to bit string
	bitString = stringToBits(input)
	print(bitString)

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

	# Run spong construction on each block
	for block in blocks:

		# XOR the block with the first r bits of the state
		for i in range(r):
			state[i] ^= block[i]

		# Run the state through the f-function
		# TODO: add f-function call

	# Get the first digestSize bits from the resulting state
	digest = state[:digestSize]

	# Process the digest into hex
	digest = digest[::-1]	# Convert back to big endian first
	digest = hex(int("".join([str(bit) for bit in digest]), 2)) # Convert to hex string
	digest = digest[2:]	# Remove the "0x" which gets added by hex()
	
	# Return the result
	return digest

result = sha3_256(input("Give some input: "))
print(result)