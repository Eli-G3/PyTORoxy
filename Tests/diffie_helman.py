import random

ALICE = 3
BOB = 84
G = 3
N = 100
print(pow(G, ALICE) % N)
print(pow(G, BOB) % N)
print(pow((pow(G, ALICE) % N), BOB) % N)
print(pow((pow(G, BOB) % N), ALICE) % N)
 

# 32 bit value b
b = int("1000000000000000000000000", 2)
print(b)
# random value a
a = random.randint(200, 2000000000)
b = b ^ a
# while the MSB of b is not 1 keep xoring with a
while bin(b)[2] != '1':
    print(b)
    a = bin(random.randint(200, 2000000000))
    b = b ^ a
print(bin(b))
print(b)
print(type(b))
print(b)

