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


# The logic behind our collision testing is simple: the dictionary data type in python
# does not allow for duplication (collision) of data, and in such as case, data will
# be overwritten rather than added. Therefore, if the input size is the same as our final
# dictionary size, then no collision occured.

# Function used to generate ramdom strings
def get_random_string(x):
    characters = ascii_letters + digits
    text = ''.join(choice(characters) for i in range(x))
    return text


# Testing the SHA3-256 library implementation
print("\nBegin Testing Library Implementation\n")

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