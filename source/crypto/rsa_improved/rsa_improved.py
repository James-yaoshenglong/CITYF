from Crypto.Util.number import getPrime
import math

# string to decimal
pt = int(open('flag.txt','rb').read().hex(),16);

primes = [];
n = 1
# euler totient
phi = 1
# public key
e = 65537

while math.log2(n) < 640:
	primes.append(getPrime(32));
	n *= (primes[-1]);
	phi *= (primes[-1] - 1);

# No duplicates
assert(len(primes) == len(list(set(primes))));
# cipher text
ct = pow(pt,e,n);

print("n = " + str(n));
print("e = 65537");
print("ct = " + str(ct));
