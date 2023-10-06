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

# MD5 ConsantV
K =    [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 
        0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 
        0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 
        0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 
        0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

# MD5 functions
def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & z) | (y & (~z))

def H(x,y,z):
    return (x ^ y ^ z)

def I(x,y,z):
    return (y ^ (x | (~z)))

def Circular_LShift(x,y):
    x = x & 0xffffffff
    return (((x) << (y)) | ((x) >> (32-(y)))) & 0xffffffff

def round1(a,b,c,d,k,s,i):
    return (b + Circular_LShift((a + F(b,c,d) + k + i),s)) & 0xffffffff

def round2(a,b,c,d,k,s,i):
    return (b + Circular_LShift((a + G(b,c,d) + k + i),s)) & 0xffffffff

def round3(a,b,c,d,k,s,i):
    return (b + Circular_LShift((a + H(b,c,d) + k + i),s)) & 0xffffffff

def round4(a,b,c,d,k,s,i):
    return (b + Circular_LShift((a + I(b,c,d) + k + i),s)) & 0xffffffff
 
def MD5(message:bytes,state:List[int]):

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
        a = round1( a,b,c,d , rounds[0]  , 7  , K[0])
        d = round1( d,a,b,c , rounds[1]  , 12 , K[1])
        c = round1( c,d,a,b , rounds[2]  , 17 , K[2])
        b = round1( b,c,d,a , rounds[3]  , 22 , K[3])
        a = round1( a,b,c,d , rounds[4]  , 7  , K[4])
        d = round1( d,a,b,c , rounds[5]  , 12 , K[5])
        c = round1( c,d,a,b , rounds[6]  , 17 , K[6])
        b = round1( b,c,d,a , rounds[7]  , 22 , K[7])
        a = round1( a,b,c,d , rounds[8]  , 7  , K[8])
        d = round1( d,a,b,c , rounds[9]  , 12 , K[9])
        c = round1( c,d,a,b , rounds[10] , 17 , K[10])
        b = round1( b,c,d,a , rounds[11] , 22 , K[11])
        a = round1( a,b,c,d , rounds[12] , 7  , K[12])
        d = round1( d,a,b,c , rounds[13] , 12 , K[13])
        c = round1( c,d,a,b , rounds[14] , 17 , K[14])
        b = round1( b,c,d,a , rounds[15] , 22 , K[15])
        
        a = round2( a,b,c,d , rounds[1]  , 5  , K[16])
        d = round2( d,a,b,c , rounds[6]  , 9  , K[17])
        c = round2( c,d,a,b , rounds[11] , 14 , K[18])
        b = round2( b,c,d,a , rounds[0]  , 20 , K[19])
        a = round2( a,b,c,d , rounds[5]  , 5  , K[20])
        d = round2( d,a,b,c , rounds[10] , 9  , K[21])
        c = round2( c,d,a,b , rounds[15] , 14 , K[22])
        b = round2( b,c,d,a , rounds[4]  , 20 , K[23])
        a = round2( a,b,c,d , rounds[9]  , 5  , K[24])
        d = round2( d,a,b,c , rounds[14] , 9  , K[25])
        c = round2( c,d,a,b , rounds[3]  , 14 , K[26])
        b = round2( b,c,d,a , rounds[8]  , 20 , K[27])
        a = round2( a,b,c,d , rounds[13] , 5  , K[28])
        d = round2( d,a,b,c , rounds[2]  , 9  , K[29])
        c = round2( c,d,a,b , rounds[7]  , 14 , K[30])
        b = round2( b,c,d,a , rounds[12] , 20 , K[31])
        
        a = round3( a,b,c,d , rounds[5]  , 4  , K[32])
        d = round3( d,a,b,c , rounds[8]  , 11 , K[33])
        c = round3( c,d,a,b , rounds[11] , 16 , K[34])
        b = round3( b,c,d,a , rounds[14] , 23 , K[35])
        a = round3( a,b,c,d , rounds[1]  , 4  , K[36])
        d = round3( d,a,b,c , rounds[4]  , 11 , K[37])
        c = round3( c,d,a,b , rounds[7]  , 16 , K[38])
        b = round3( b,c,d,a , rounds[10] , 23 , K[39])
        a = round3( a,b,c,d , rounds[13] , 4  , K[40])
        d = round3( d,a,b,c , rounds[0]  , 11 , K[41])
        c = round3( c,d,a,b , rounds[3]  , 16 , K[42])
        b = round3( b,c,d,a , rounds[6]  , 23 , K[43])
        a = round3( a,b,c,d , rounds[9]  , 4  , K[44])
        d = round3( d,a,b,c , rounds[12] , 11 , K[45])
        c = round3( c,d,a,b , rounds[15] , 16 , K[46])
        b = round3( b,c,d,a , rounds[2]  , 23 , K[47])

        a = round4( a,b,c,d , rounds[0]  , 6  , K[48])
        d = round4( d,a,b,c , rounds[7]  , 10 , K[49])
        c = round4( c,d,a,b , rounds[14] , 15 , K[50])
        b = round4( b,c,d,a , rounds[5]  , 21 , K[51])
        a = round4( a,b,c,d , rounds[12] , 6  , K[52])
        d = round4( d,a,b,c , rounds[3]  , 10 , K[53])
        c = round4( c,d,a,b , rounds[10] , 15 , K[54])
        b = round4( b,c,d,a , rounds[1]  , 21 , K[55])
        a = round4( a,b,c,d , rounds[8]  , 6  , K[56])
        d = round4( d,a,b,c , rounds[15] , 10 , K[57])
        c = round4( c,d,a,b , rounds[6]  , 15 , K[58])
        b = round4( b,c,d,a , rounds[13] , 21 , K[59])
        a = round4( a,b,c,d , rounds[4]  , 6  , K[60])
        d = round4( d,a,b,c , rounds[11] , 10 , K[61])
        c = round4( c,d,a,b , rounds[2]  , 15 , K[62])
        b = round4( b,c,d,a , rounds[9]  , 21 , K[63])

        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff
    
    H = [A,B,C,D]

    return b"".join([f.to_bytes(4,"little") for f in H]).hex()


