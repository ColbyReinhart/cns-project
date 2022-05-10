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
outbits = 256