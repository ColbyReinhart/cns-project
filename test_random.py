# Collision testing for SHA3-256
# Colby Reinhart, Tyler Gargasz
# CS-45203: Computer Network Security
# 5-06-2022

# USAGE:
# Requires python 3.10.0 or higher
# run with "python test_collision.py"

import hashlib
import sha3

def compare(x, y) : 
    changes = 0
    for i in range(len(x)) :
        if x[i] != y[i] :
            changes += 1
    return changes

#
# Library Implementation
#

print("\nBegin Testing Library Implementation\n")

test1 = "Hello World!"
hash1 = hashlib.sha256(test1.encode('utf-8')).hexdigest()
print("\tHello World! ->", hash1)

test2 = "Hello World?"
hash2 = hashlib.sha256(test2.encode('utf-8')).hexdigest()
print("\tHello World? ->", hash2)

print("\tTotal Differences:", compare(hash1, hash2))


test1 = "Tyler"
hash1 = hashlib.sha256(test1.encode('utf-8')).hexdigest()
print("\tTyler ->", hash1)

test2 = "tyler"
hash2 = hashlib.sha256(test2.encode('utf-8')).hexdigest()
print("\ttyler ->", hash2)

print("\tTotal Differences:", compare(hash1, hash2))

print("\nDone testing Library Implementation")

#
# Our Implementation
#

print("\nBegin Testing Our Implementation\n")

test1 = "Hello World!"
hash1 = sha3.sha3_256(test1)
print("\tHello World! ->", hash1)

test2 = "Hello World?"
hash2 = sha3.sha3_256(test2)
print("\tHello World? ->", hash2)

print("\tTotal Differences:", compare(hash1, hash2))


test1 = "Tyler"
hash1 = sha3.sha3_256(test1)
print("\tTyler ->", hash1)

test2 = "tyler"
hash2 = sha3.sha3_256(test2)
print("\ttyler ->", hash2)

print("\tTotal Differences:", compare(hash1, hash2))

print("\nDone testing Library Implementation")