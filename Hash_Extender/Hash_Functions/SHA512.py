from typing import List

# Default State
def Default_State(): 
    return [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]

def seperate(p): 
    final = []
    blocks = [p[x:x+128] for x in range(0,len(p),128)]
    for b in blocks:
        final.append([int.from_bytes(b[x:x+8],"big") for x in range(0,len(b),8)])

    return final

K = bytearray.fromhex("428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc"
                      "3956c25bf348b53859f111f1b605d019923f82a4af194f9bab1c5ed5da6d8118"
                      "d807aa98a303024212835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e2"
                      "72be5d74f27b896f80deb1fe3b1696b19bdc06a725c71235c19bf174cf692694"
                      "e49b69c19ef14ad2efbe4786384f25e30fc19dc68b8cd5b5240ca1cc77ac9c65"
                      "2de92c6f592b02754a7484aa6ea6e4835cb0a9dcbd41fbd476f988da831153b5"
                      "983e5152ee66dfaba831c66d2db43210b00327c898fb213fbf597fc7beef0ee4"
                      "c6e00bf33da88fc2d5a79147930aa72506ca6351e003826f142929670a0e6e70"
                      "27b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df"
                      "650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353b"
                      "a2bfe8a14cf10364a81a664bbc423001c24b8b70d0f89791c76c51a30654be30"
                      "d192e819d6ef5218d69906245565a910f40e35855771202a106aa07032bbd1b8"
                      "19a4c116b8d2d0c81e376c085141ab532748774cdf8eeb9934b0bcb5e19b48a8"
                      "391c0cb3c5c95a634ed8aa4ae3418acb5b9cca4f7763e373682e6ff3d6b2b8a3"
                      "748f82ee5defb2fc78a5636f43172f6084c87814a1f0ab728cc702081a6439ec"
                      "90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915c67178f2e372532b"
                      "ca273eceea26619cd186b8c721c0c207eada7dd6cde0eb1ef57d4f7fee6ed178"
                      "06f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b"
                      "28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c"
                      "4cc5d4becb3e42b6597f299cfc657e2a5fcb6fab3ad6faec6c44198c4a475817")

K_blocks = [int.from_bytes(K[x:x+8],"big") for x in range(0,len(K),8)]


# SHA-512 Functions
def Shift_Right(x,y):
    return x >> y 

def Rotate_Right(x,y):
    return (x >> y) | (x << (64 - y)) & 0xFFFFFFFFFFFFFFFF

def sigma0(x):
    return Rotate_Right(x,1) ^ Rotate_Right(x,8) ^ Shift_Right(x,7)

def sigma1(x):
    return Rotate_Right(x,19) ^ Rotate_Right(x,61) ^ Shift_Right(x,6)

def Ch(x,y,z):
    return (x & y) ^ (~x & z)

def Maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return Rotate_Right(x,28) ^ Rotate_Right(x,34) ^ Rotate_Right(x,39)

def Sigma1(x):
    return Rotate_Right(x,14) ^ Rotate_Right(x,18) ^ Rotate_Right(x,41)



def sha512(message,state:List[int]):

    H = state
    
    padded_message = seperate(message) # W[:16]

    Total_Blocks = len(padded_message) # How many blocks

    for i in range(Total_Blocks):

        
        rounds = [padded_message[i-1][v] for v in range(16)]

        # Prepare the rounds
        for w in range(16,80): # W[16:80]
            rounds.append((sigma1(rounds[w-2]) + rounds[w-7] + sigma0(rounds[w-15]) + rounds[w-16]) & 0xFFFFFFFFFFFFFFFF)
        
        # Current state initialization
        a,b,c,d,e,f,g,h = H

        # Shuffling
        for t in range(80):
            T1 = (h + Sigma1(e) + Ch(e,f,g) + K_blocks[t] + rounds[t]) & 0xFFFFFFFFFFFFFFFF
            T2 = (Sigma0(a) + Maj(a,b,c)) & 0xFFFFFFFFFFFFFFFF
            h = g 
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFFFFFFFFFF
            d = c 
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFFFFFFFFFF
        
        # Final state of I-th block
        H[0] += a 
        H[1] += b 
        H[2] += c 
        H[3] += d 
        H[4] += e 
        H[5] += f 
        H[6] += g 
        H[7] += h 
        H = [h & 0xFFFFFFFFFFFFFFFF for h in H]

    # Return H0||H1||H2||H3||H4||H5||H6||H7
    return b"".join([f.to_bytes(8,"big") for f in H]).hex()

