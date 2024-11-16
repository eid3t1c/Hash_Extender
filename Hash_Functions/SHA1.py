from typing import List

def Default_State(): 
    return [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


# SHA-1 Functions
def Ch(x,y,z):
    return (x & y) ^ (~x & z)

def Maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def Parity(x,y,z):
    return x ^ y ^ z

def Rotate_Left(x,y):
    return ((x << y) | (x >> (32-y))) & 0xFFFFFFFF

K = [0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6]


def sha1(message:bytes,state:List[int]):

    # Default State
    H = state
    final = []
    blocks = [message[x:x+64] for x in range(0,len(message),64)]
    for b in blocks:
        final.append([int.from_bytes(b[x:x+4],"big") for x in range(0,len(b),4)])

    padded_message = final # W[:16]

    # How many blocks
    Total_Blocks = len(padded_message) 

    for i in range(Total_Blocks):

        rounds = [padded_message[i][v] for v in range(16)]

        # Prepare the rounds
        for w in range(16,80): # W[16:80]
            rounds.append(Rotate_Left(rounds[w-3] ^ rounds[w-8] ^ rounds[w-14] ^ rounds[w-16],1) & 0xFFFFFFFF)
        
        # Current state initialization
        a,b,c,d,e = H
        
        # Shuffling
        for t in range(80):
            if t < 20:
                T = (Rotate_Left(a,5) + Ch(b,c,d) + e + K[0] + rounds[t]) & 0xFFFFFFFF
            elif t < 40:
                T = (Rotate_Left(a,5) + Parity(b,c,d) + e + K[1] + rounds[t]) & 0xFFFFFFFF
            elif t < 60:
                T = (Rotate_Left(a,5) + Maj(b,c,d) + e + K[2] + rounds[t]) & 0xFFFFFFFF
            else:
                T = (Rotate_Left(a,5) + Parity(b,c,d) + e + K[3] + rounds[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = Rotate_Left(b,30)
            b = a
            a = T
        
        # Final state of I-th block
        H[0] += a
        H[1] += b 
        H[2] += c 
        H[3] += d 
        H[4] += e
        H = [h & 0xFFFFFFFF for h in H]

    # Return H0||H1||H2||H3||H4
    return b"".join([f.to_bytes(4,"big") for f in H]).hex()
