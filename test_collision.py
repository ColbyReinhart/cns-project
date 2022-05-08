# Collision testing for SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 5-06-2022

# USAGE:
# Requires python 3.10.0 or higher
# run with "python test_collision.py"

import hashlib                              # Library containing another implementation of SHA3-256
from random import choice, randint          # Used to randomly select characters and numbers 
from string import ascii_letters,  digits   # ASCII character (lower and upper), and digits 0-9


# Creating large array of inputs
# Words.txt contains 58110 entries
# If the output size is equal to the input size, then there is no collision

# Function used to generate ramdom strings
def get_random_string(x):
    characters = ascii_letters + digits
    text = ''.join(choice(characters) for i in range(x))
    return text


# Testing the SHA3-256 library implementation
print("Begin Testing Library Implementation\n")

testSize = int(input("Input Number of tests to run: "))

index = 0
testOutput = {}
#testSize = 1000
for t in range(testSize) :
    inputSize = randint(1000, 100000)
    input = get_random_string(inputSize)
    hash = hashlib.sha256(input.encode('utf-8')).hexdigest()
    if randint(1,10) == 10:
        print("\tTest", t)
        # print("\tInput:", input)
        print("\tHash:", hash)
    testOutput[index] = hash
    index += 1

print("\n\tNumber of Inputs:\t", testSize)
print("\tNumber of Outputs:\t", len(testOutput), '\n')

if testSize == len(testOutput) :
    print("No Collision, Testing Successful!")
else : 
    print("Collisions Detected, Testing Failed!")


print("\nDone testing Library Implementation")