# **Hash_Extender**

An automated tool implementing Hash Length Extension attack on ```MD4```,```MD5```,```SHA1```,```SHA256``` and ```SHA512```

# Help Menu

```bash 
Python Length_Extender.py -h
```
Or **if installed with pip**
```cmd 
lenext -h
``` 


![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/ab271662-4df0-48be-b87d-4d58fa695136)

# Usage

## With arguments

```cmd
python Length_Extender.py -f SHA1 -s efb6be6e9ae5ff61092e409427d44a7fa4f4cc23  -d secret -e admin=True -k 40
``` 
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/e2c42923-3c5d-40ed-98d9-7e2799e01748)



## Without arguments

```cmd 
python Length_Extender.py
```

```cmd
Select Hash Function >  MD5
Insert Signature >  4f60686e87b0f6a21109a77a63bc6a7b
Insert Known Data [Leave Empty if None] >  Freaks
Insert Extra Data >  Every_Single_Night
Insert Key Length >  40
```
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/ed547cb8-6078-4ec0-941d-4589b0d6a433)

# Installation with PIP

```cmd
git clone git@github.com:eid3t1c/Length_Extender.git
```
```cmd
cd Hash_Extender
```
```cmd
sudo pip install .
```
### You can now use the tool by the name ```lenext```
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/f29d330d-a424-49cf-bb54-7b5f63fce4ae)


# What is Length Extension Attack

A ```length extension attack``` is a type of security exploit where an adversary leverages knowledge of the hash value of a key, along with the length of that key, to compute the hash of an ```attacker-controlled additional message``` (referred to as message2), all without requiring any knowledge of the original content of key. This attack becomes particularly problematic when a hash function is used as part of a message authentication code construction in the form of Hash(key ‖ message). In situations where the length of the key and message is known to the attacker, this vulnerability can be exploited to append extra information to the message, creating a valid hash without the need for knowledge of the secret key. This vulnerability is especially pronounced in algorithms like ```MD5```, ```SHA-1```, and many ```SHA-2``` variants, which are constructed based on the ```Merkle–Damgård construction```.

# Why is Length Extension Attack feasible

## Merkle–Damgård construction

The Merkle-Damgard construction is a technique used to create secure hash functions from compression functions when working with fixed-size blocks, such as 64 bytes in the case of SHA-256. Even if the input message's size is not a perfect multiple of this block size, we always add padding, ensuring it fits.

The way padding works:

Message Block = **B** <br>
Number of bytes used for message length = **L** <br>
Hash State = **N**

Input Message: Suppose we have a message, let's call it "secret," that we want to hash.

1. Appending the Start of Padding: the hash function begins by appending a single byte \x80 to the end of the message. This byte acts as a marker indicating the start of the padding process.
2. Adding Zero Bytes: To ensure that the message length becomes a specific value, the hash function repeatedly adds the byte \x00 until the total length of the message reaches ``` B - L``` bytes.
3. The ramaining L bytes are used to represent the length of the message in bits.

### For Example in SHA-256

message = "secret" = 6 bytes
1. append \x80 -> ```"secret\x80"```
2. append \x00 until block length is 56 (SHA-256 block size is 64) ```"secret\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"```
3. Convert the **length** of the message in bits (**length** * 8 ) and represent the result as 8 bytes.
   ```python
   (6*8).to_bytes(8,byteorder="big") = \x00\x00\x00\x00\x00\x00\x000
   ```

padded message = ```secret + \x80 + \x00 * 49 + \x00\x00\x00\x00\x00\x00\x000```


This padded message is processed from a compression function which processes the two inputs, one **N** bits long and the other **B** bits long, to produce an **N** bit output.
### **The N bit output is then passed as a new state to the compression function to process the next block of message.**

![image](https://github.com/eid3t1c/hash_cryptohack/assets/102302619/4a852c99-b4a4-42c9-bfdd-573816e348c4)


## Why is Merkle–Damgård construction a problem

Let's assume the following Authentication System:

The authentication system has a secret key of length 40.

### To authenticate a user or entity, the system requests two pieces of information:

1. Passcode: This is something the user provides.
2. Signature: This is also provided by the user.

### Hashing Process:

The system uses the SHA-256 hashing algorithm to process the data.
It **pre-pends** the secret key  and the user-provided passcode.
It then calculates the SHA-256 hash of the concatenated "Key + passcode"

### Comparison:

The system compares the calculated hash with the user-provided signature.
### Authentication Result:

If the calculated hash and the user-provided signature match, the authentication is successful.
This means only the admin who knows the secret key could produce the same hash as the system.

# Length Extension implement

By sending the word  ```administrator ``` i receive the hash ```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97```
If i were to know that the key lengths is 40 i could easily produce a valid signature and authenticate without knowing the actual value of the key.

## How

I do know how the ```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97``` was produced.

![image](https://github.com/eid3t1c/hash_cryptohack/assets/102302619/a3c56a36-81b1-4f84-b955-64a88922f807)

I choose the control data to be  ```Mister M6 ```

I will send to the server the message ```administrator (13) + \x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8 (11) + Mister M6 (9)``` = 33

## WHY

Because the server will prepend its key ``` key (40) + admninistrator (13) + \x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8 (11) + Mister M6 (9)``` = 73
1. It will consider it a message of 73 bytes.
2. It will pad it
3. And it will seperate it to blocks

Block1 =  ```key (40) + admninistrator (13) + \x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8 (11) ``` = 64 
<br>
<br>
Length_of_message = (Block1 (64) + Mister M6 (9)) * 8 = ```\x00\x00\x00\x00\x00\x00\x02H```
<br>
Block2 =  ```Mister M6 (9) + \x80 + \x00 (46)``` + **Length_of_message** (8)   = 64

![image](https://github.com/eid3t1c/hash_cryptohack/assets/102302619/4d5c6dca-9312-46f0-b461-338bc1443857)

Notice how the hash of the first block which we know is ```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97``` is used as a state for SHA-256, in order for ```Block2``` which we also know how its padded to get hashed, for the final hash aka ```signature``` to be produced.

So if i use SHA-256 with default state the hash ```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97``` to hash ```Mister M6 (9) + \x80 + \x00 (46) + Length_of_message (8)``` i will produce the same signature as the server and i will be authenticated without knowing the key.

So thanks to ```Merkle–Damgård``` construction i can mimic the ```SHA-256``` and hash the ```Block2``` message with the hash of ```Block1```

```python
from hashlib import sha256
import os
from SHA256 import sha256 as SHA256


# Split the hash from Big-endian hash functions [Sha1, Sha256, Sha512]
def Bendian_STATE(signature,digest_size,state_blocks):
    state = []
    if len(signature) != digest_size:
        raise ValueError(f"The input hash must be {digest_size} bytes long.")
    for i in range(0,len(signature),digest_size//state_blocks):
        temp = signature[i:i+digest_size//state_blocks]
        state.append(int(temp,16))
    return state

# 40 random bytes 
key = os.urandom(40)

Given_Hash = sha256(key+ b"administrator").hexdigest()
# bf36e8e8455aebcf7f8a0f4a421a2435522e3fe9f33c01100af72c14bf806670

Append = b"Mister M6"
# Block length = 64 , Length of key = 40 , Length of known message = 13 , -1 for the \x80 , - 8 for the Length of block bytes
Msg_For_Server = b"administrator" + b"\x80" + b"\x00" * (64 - 40 - 13 - 1 - 8) + (53*8).to_bytes(8,byteorder="big") + Append

# block1 is 64 bytes of message + 9 bytes of the message "Mister M6" = 73
Total_Length = (64 + 9)*8
# Mister M6 = 9 , -1 for the \x80 , - 8 for the Length of block bytes
Block2 = b"Mister M6" + b"\x80" + b"\x00" * (64 - 9 - 1 - 8) + Total_Length.to_bytes(8,byteorder="big")

# Split the hash into 8 equal parts since thats how SHA-256 functions.
state = Bendian_STATE(Given_Hash,64,8)

# My implementation of SHA-256 without padding and custom state
Signature = SHA256(Block2,state)

# Assert we computed the same Hash
assert Signature == sha256(key+Msg_For_Server).hexdigest()
print(f"God bless Merkle–Damgård construction because {Signature} = {sha256(key+Msg_For_Server).hexdigest()}")
```

```cmd
God bless Merkle–Damgård construction because dba7e16212b7e07763d5771e01a6ea04cba12c0ab147ac00644b78e95168aeb6 = dba7e16212b7e07763d5771e01a6ea04cba12c0ab147ac00644b78e95168aeb6
```



