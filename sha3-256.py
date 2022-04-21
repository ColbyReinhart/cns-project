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
			result.append([])
			for z in range(w):
				value = (w * ((5 * y) + x) + z)				# generate value
				if (value < b):								# Index the string
					result[x][y].append(int(input[value]))	# Fill in the state
	return result

