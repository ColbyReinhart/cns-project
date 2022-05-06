# A testfile for our implementation of SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 5-06-2022

# USAGE:
# Requires python 3.10.0 or higher
# run with "python test_collision.py"

import hashlib  # Library containing another implementation of SHA3-256

# Creating large array of inputs
# Words.txt contains 58110 entries
file = open("words.txt", 'r')
testInput = file.readlines()
file.close() 


# Testing the SHA3-256 library implementation
index = 0
testOutput = {}
for proCase in testInput :
    hash = hashlib.sha256(proCase.encode('utf-8')).hexdigest()
    testOutput[index] = hash
    index += 1
    #testOutput.append(hash)
    #print(proCase, " = ", hash)

# DO NOT UNCOMMENT LINE BELOW
#print(testOutput)
print("Input Array Size: ", len(testInput))
print("Output Array Size: ", len(testOutput))