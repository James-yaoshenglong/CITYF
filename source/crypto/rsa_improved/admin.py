#from Crypto.Util.number import getPrime
import math

# string to decimal
pt = int(open('flag.txt','rb').read().hex(),16);

primes = [ 2151055861, 2319991937, 2341310833, 2391906757, 2448497717,
 2493514393, 2586983803, 2758321513, 2784469417, 2816940109, 2865965429,
 3092165243, 3218701459, 3438516511, 3526137361, 3663803701, 3673658161,
 3789550043, 3866428117, 3919632263, 4147385899]
n = 1
# euler totient
phi = 1
# public key
e = 65537

for num in primes:
    n *= (num);
    phi *= (num - 1);

# No duplicates
assert(len(primes) == len(list(set(primes))));
# cipher text
ct = pow(pt,e,n);

print("n = " + str(n));
print("e = 65537");
print("ct = " + str(ct));
#print(decrypt(ct))
