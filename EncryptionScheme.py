
# Cook's scheme: http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=A1E926EE76BF2558D323DE8105F4F8C4?doi=10.1.1.208.6433&rep=rep1&type=pdf
import hashlib
 # +1 = 1
 # -1 = 0
def jacobi (a, m):
	j = 1
	a %= m
	while a : 
		t = 0
		while not a & 1:
			a = a >> 1
			t += 1
		if t & 1 and m % 8 in (3, 5):
			j = -j
		if (a % 4 == m % 4 == 3):
			j = -j
		a, m = m % a, a
	return j if m == 1 else 0

def PKG(pubId, p, q):
    M = p * q
    jacobiSymbol = 0
    a = bytes(pubId, encoding='utf-8')
    while(jacobiSymbol != 1): # Keep on hashing until jacobi symbol is 1. 
        sha1 = hashlib.sha1()
        sha1.update(a)
        a = sha1.digest()
        jacobiSymbol = jacobi(int(a.hex(), 16), M)
    print("a =", a.hex())
    a = int(a.hex(), 16)
    exp = (M + 5 - (p + q)) // 8
    r =  pow(a, exp, mod = M)
    return r
    
def decrypt(encryptedBits, r, M ):
    decryptedBits = list()
    for bit in encryptedBits:
        jacobiSymbol = jacobi(bit + 2*r, M)
        if(jacobiSymbol == -1):
            jacobiSymbol = 0
        decryptedBits.append(str(jacobiSymbol))
    return decryptedBits

if __name__ == "__main__":
    publicIdentity = 'walterwhite@crypto.sec'
    p = 0x9240633d434a8b71a013b5b00513323f
    q = 0xf870cfcd47e6d5a0598fc1eb7e999d1b
    r = PKG(publicIdentity, p, q) # Private key. 
    print('Private key =', hex(r)[2:])
    encryptedBits = [
                        0x2f2aa07cfb07c64be95586cfc394ebf26c2f383f90ce1d494dde9b2a3728ae9b,
                        0x63ed324439c0f6b823d4828982a1bbe5c34e66d985f55792028acd2e207daa4f,
                        0x85bb7964196bf6cce070a5e8f30bc822018a7ad70690b97814374c54fddf8e4b,
                        0x30fbcc37643cc433d42581f784e3a0648c91c9f46b5671b71f8cc65d2737da5c,
                        0x5a732f73fb288d2c90f537a831c18250af720071b6a7fac88a5de32b0df67c53,
                        0x504d6be8542e546dfbd78a7ac470fab7f35ea98f2aff42c890f6146ae4fe11d6,
                        0x10956aff2a90c54001e85be12cb2fa07c0029c608a51c4c804300b70a47c33bf,
                        0x461aa66ef153649d69b9e2c699418a7f8f75af3f3172dbc175311d57aeb0fd12
                    ]
    decryptedBits = decrypt(encryptedBits, r, p * q)

    print('decrypted number =', int("".join(decryptedBits), 2))
