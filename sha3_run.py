# A simple file to run our implementation
# Colby Reinhart, Tyler Gargasz
# 5-11-2022

# Usage: python sha3_run.py
# You will be prompted for input and will receive output via console

from sha3 import sha3_256

message = input("Provide a message to hash: ")
print(sha3_256(message))