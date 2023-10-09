from typing import List

# Default State
def Default_State(): 
    return [0x67452301,0xefcdab89,0x98badcfe,0x10325476]


def seperate(p): 
    final = []
    blocks = [p[x:x+64] for x in range(0,len(p),64)]
    for b in blocks:
        final.append([int.from_bytes(b[x:x+4],"little") for x in range(0,len(b),4)])
    
    return  final

# MD4 functions
def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return (x ^ y ^ z)

def Circular_LShift(x,y):
    x = x & 0xffffffff
    return (((x) << (y)) | ((x) >> (32-(y)))) & 0xffffffff

def round1(a,b,c,d,k,s):
    return (Circular_LShift((a + F(b,c,d) + k),s)) & 0xffffffff

def round2(a,b,c,d,k,s):
    return (Circular_LShift((a + G(b,c,d) + k + 0x5A827999),s)) & 0xffffffff

def round3(a,b,c,d,k,s):
    return (Circular_LShift((a + H(b,c,d) + k + 0x6ED9EBA1),s)) & 0xffffffff

 
def MD4(message:bytes,state:List[int]):

    # Default MD4 state
    Registers = state
    
    
    seperated = seperate(message)
    # How many blocks
    blocks = len(seperated)

    A,B,C,D = Registers
    for i in range(blocks):

        rounds = [seperated[i][v] for v in range(16)]

        a,b,c,d = A,B,C,D
        # Shuffling rounds
        a = round1( a,b,c,d , rounds[0]  , 3  )
        d = round1( d,a,b,c , rounds[1]  , 7  )
        c = round1( c,d,a,b , rounds[2]  , 11 )
        b = round1( b,c,d,a , rounds[3]  , 19 )
        a = round1( a,b,c,d , rounds[4]  , 3  )
        d = round1( d,a,b,c , rounds[5]  , 7  )
        c = round1( c,d,a,b , rounds[6]  , 11 )
        b = round1( b,c,d,a , rounds[7]  , 19 )
        a = round1( a,b,c,d , rounds[8]  , 3  )
        d = round1( d,a,b,c , rounds[9]  , 7  )
        c = round1( c,d,a,b , rounds[10] , 11 )
        b = round1( b,c,d,a , rounds[11] , 19 )
        a = round1( a,b,c,d , rounds[12] , 3  )
        d = round1( d,a,b,c , rounds[13] , 7  )
        c = round1( c,d,a,b , rounds[14] , 11 )
        b = round1( b,c,d,a , rounds[15] , 19 )

        a = round2( a,b,c,d , rounds[0]  , 3  )
        d = round2( d,a,b,c , rounds[4]  , 5  )
        c = round2( c,d,a,b , rounds[8]  , 9  )
        b = round2( b,c,d,a , rounds[12] , 13 )
        a = round2( a,b,c,d , rounds[1]  , 3  )
        d = round2( d,a,b,c , rounds[5]  , 5  )
        c = round2( c,d,a,b , rounds[9]  , 9  )
        b = round2( b,c,d,a , rounds[13] , 13 )
        a = round2( a,b,c,d , rounds[2]  , 3  )
        d = round2( d,a,b,c , rounds[6]  , 5  )
        c = round2( c,d,a,b , rounds[10] , 9  )
        b = round2( b,c,d,a , rounds[14] , 13 )
        a = round2( a,b,c,d , rounds[3]  , 3  )
        d = round2( d,a,b,c , rounds[7]  , 5  )
        c = round2( c,d,a,b , rounds[11] , 9  )
        b = round2( b,c,d,a , rounds[15] , 13 )

        a = round3( a,b,c,d , rounds[0]  ,  3 )
        d = round3( d,a,b,c , rounds[8]  ,  9 )
        c = round3( c,d,a,b , rounds[4]  , 11 )
        b = round3( b,c,d,a , rounds[12] , 15 )
        a = round3( a,b,c,d , rounds[2]  , 3  )
        d = round3( d,a,b,c , rounds[10] , 9  )
        c = round3( c,d,a,b , rounds[6]  , 11 )
        b = round3( b,c,d,a , rounds[14] , 15 )
        a = round3( a,b,c,d , rounds[1]  , 3  )
        d = round3( d,a,b,c , rounds[9]  , 9  )
        c = round3( c,d,a,b , rounds[5]  , 11 )
        b = round3( b,c,d,a , rounds[13] , 15 )
        a = round3( a,b,c,d , rounds[3]  , 3  )
        d = round3( d,a,b,c , rounds[11] , 9  )
        c = round3( c,d,a,b , rounds[7]  , 11 )
        b = round3( b,c,d,a , rounds[15] , 15 )
        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff
    
    H = [A,B,C,D]

    return b"".join([f.to_bytes(4,"little") for f in H]).hex()

