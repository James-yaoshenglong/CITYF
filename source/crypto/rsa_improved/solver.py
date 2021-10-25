e = 65537
c = 211405536766990282392865501759551800709384632801043524136369092465438060458383313392448120404966100032071512835009748019864826645835900007662105569966372367175168288606224680876958858355480036772390

n = 10588750243470683238253385410274703579658358849388292003988652883382013203466393057371661939626562904071765474423122767301289214711332944602077015274586262780328721640431549232327069314664449442016399

# primes are factored from n
primes = [ 2151055861, 2319991937, 2341310833, 2391906757, 2448497717,
 2493514393, 2586983803, 2758321513, 2784469417, 2816940109, 2865965429,
 3092165243, 3218701459, 3438516511, 3526137361, 3663803701, 3673658161,
 3789550043, 3866428117, 3919632263, 4147385899]  
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

ts = []
xs = []
ds = []

for i in range(len(primes)):
	ds.append(modinv(e, primes[i]-1))

m = primes[0]

for i in range(1, len(primes)):
	ts.append(modinv(m, primes[i]))
	m = m * primes[i]

for i in range(len(primes)):
	xs.append(pow((c%primes[i]), ds[i], primes[i]))

x = xs[0]
m = primes[0]

for i in range(1, len(primes)):
	x = x + m * ((xs[i] - x % primes[i]) * (ts[i-1] % primes[i]))
	m = m * primes[i]


print hex(x%n)[2:-1].decode("hex")
