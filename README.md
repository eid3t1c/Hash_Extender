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

A **<span style="color:red">length extension attack</span>** is a type of security exploit where an HMAC of the form `Hash(Secret Key || Message)` is used. An adversary leverages knowledge of a **<span style="color:#0066cc">Message</span>**, its corresponding **<span style="color:#9999ff">Hash</span>**, and the length of the **<span style="color:#b36b00">Secret Key</span>** to compute a valid hash of an `attacker-controlled additional message` (referred to as **<span style="color:#0066cc">Message2</span>**), all without requiring any knowledge of the original content of the key.

This vulnerability is especially pronounced in algorithms that use the `Merkle–Damgård construction` and do not truncate the final hash. Known algorithms like `MD5`, `SHA-1`, and many `SHA-2` variants are susceptible to this attack.


# Why is Length Extension Attack feasible

## Merkle–Damgård Construction

The `Merkle–Damgård` construction is a technique used to create secure hash functions from compression functions when working with fixed-size blocks, such as 64 bytes in the case of SHA-256. Even if the input message's size is not a perfect multiple of this block size, padding is always added to ensure it fits.

### The Way Padding Works:

For `Hash Function` = SHA-256, `Block_Size` = 64 bytes, and `Message` = "The black sheep that wanted to feel free":

Every `Hash Function` uses a fixed number of bytes to store the message length. SHA-256 represents the message's length as an 8-byte value.

**Example Workflow:**

1. **Appending the Start of Padding**:  
   The hash function begins by appending a single byte `\x80` to the end of the message. This byte acts as a marker indicating the start of the padding process.

2. **Adding Zero Bytes**:  
   To ensure that the message length aligns with the required block size, the hash function repeatedly adds the byte `\x00` until the total length of the padded message reaches `B - L` bytes.  

   - Here, `B` is the block size (64 bytes for SHA-256), and `L` is the length of the message representation (8 bytes).

3. **Adding the Length of the Original Message**:  
   The remaining `L` bytes are used to represent the length of the original message in bits, as an 8-byte value.


### **Note on Endianness:**

Some hash functions represent the length of the original message as either **Big Endian** or **Little Endian**.

- **Big Endian**: SHA-1, SHA-2 famillies
- **Little Endian**: MD familly

<a href="https://www.freecodecamp.org/news/what-is-endianness-big-endian-vs-little-endian/">More Info</a>


### Example of Padding:

**Input Message**: "The black sheep that wanted to feel free"  

**Padded Output**:

```html
                Message                                              Padding                                     Length of the message
|----------------------------------------|-----------------------------------------------------------------|--------------------------------|
 The black sheep that wanted to feel free \x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00   \x00\x00\x00\x00\x00\x00\x01@
```

This is then handled by the compression function and results to `1adfd47d1a16c931d36e9b79622db9f50c92df73cba0c535f685e33a34c32fa7`

Using my own SHA-256 where I can print some internal values.
```python
Message = b"The black sheep that wanted to feel free"
SHA256(Message)
```

```cmd
Input Message: The black sheep that wanted to feel free
Message Length: 40
Padded Message: The black sheep that wanted to feel free\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01@
SHA256 Hash: 1adfd47d1a16c931d36e9b79622db9f50c92df73cba0c535f685e33a34c32fa7
```
The above is one block. If a message larger than 56 bytes was given we would have two or more blocks.

This padded message is processed from a compression function which processes the two inputs, one **N** bits long and the other **B** bits long, to produce an **N** bit output.


![image](https://github.com/eid3t1c/Hash_Extender/assets/102302619/bea32df7-8b2d-46aa-8c49-31fcf7021548)



## Why is Merkle–Damgård Construction a Problem

Let's consider the following authentication system:

### The Authentication System:

The system uses a **secret key** of length **40** bytes.

### To Authenticate a User or Entity, the System Requests Two Pieces of Information:

1. **Passcode**: Provided by the user.
2. **Signature**: Also provided by the user.

### Hashing Process:

1. The system uses the SHA-256 hashing algorithm to process the data.
2. It **pre-pends** the secret key to the user-provided passcode.
3. It calculates the SHA-256 hash of the concatenated string: `SHA256(Key || Passcode)`.

### Comparison:

- The system calculates the hash and compares it with the user-provided signature.
- If the calculated hash matches the signature, the authentication is successful.
- This implies that only someone who knows the **secret key** could generate a valid hash.

---

## Length Extension Attack in Action

Consider the following scenario:

1. By sending the passcode `administrator`, I receive the hash:  
   `63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97`.

2. Knowing the secret key's length is **40 bytes**, I can exploit the Merkle–Damgård construction to produce a valid signature **without knowing the actual key value**.


### How

I do know how the ```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97``` was produced.

![image](https://github.com/eid3t1c/Hash_Extender/assets/102302619/2775ed2b-3222-44fd-a1e5-c9da3fbd5513)


I choose the control data to be  ```Mister M6 ```

I will send to the server the message ```administrator\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8Mister M6``` = 33

### Why Length Extension Attacks Work

The vulnerability arises because the server pre-pends its secret key and computes the hash in the form:  
`HASH(Key || Message)`.

---

### Example Padding and Blocks

The server processes the following message:

```html
                         Message (73 bytes)                                           Padding                    Length of the message(8)
|---------------------------------------------------------------------|-----------------------------------|------------------------------|
 keyadministrator\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8Mister M6 \x80\x00\x00\x00...\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x02H
```
``` keyadmninistrator\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8Mister M6``` = 73

- The server considers this as a 73-byte message.

- Padding is added to align it with the block size.

- The server splits it into blocks for SHA-256 processing:

Block1 =  ```keyadministrator\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa8``` = 64 

Block2 = ```Mister M6\x80\x00\x00\x00...\x00\x00\x00\x00 x00\x00\x00\x00\x00\x00\x02H``` = 64
<br>


![image](https://github.com/eid3t1c/Hash_Extender/assets/102302619/21c69369-d28a-4ba9-8354-bc66bb7917c1)


Notice how the hash of the first block, which we know is:
```63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97``` can be used as the state for SHA-256, allowing the second block (`Block2`) to be hashed along with its padding to produce the final hash (signature).

So, to perform a **length extension attack**, we can "mimic" the SHA-256 process. Starting with the known hash of `Block1` (which is the current state of the hash function), we can extend the message (which would be `Mister M6\x80\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02H` ) and compute the final hash to match the signature.

This works because the **Merkle–Damgård** construction, which is used in SHA-256, allows you to append data and continue the hash computation from the current state (the hash of `Block1`), essentially bypassing the need for the original message content or the key.

### Example Code

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



