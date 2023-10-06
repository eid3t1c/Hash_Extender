from Hash_Functions import MD4,MD5,SHA1,SHA256,SHA512
import argparse


# Split the hash from Big-endian hash functions [Sha1, Sha256, Sha512]
def Bendian_STATE(signature,digest_size,state_blocks):
    state = []
    if len(signature) != digest_size:
        raise ValueError(f"The input hash must be {digest_size} bytes long.")
    for i in range(0,len(signature),digest_size//state_blocks):
        temp = signature[i:i+digest_size//state_blocks]
        state.append(int(temp,16))
    return state


# Split the hash from Little-endian hash functions [MD4, MD5]
def Lendian_STATE(signature):
    if len(signature) != 32:
        raise ValueError("The input hash must be 32 bytes long.")
    # Split the hash into 4 equal parts
    parts = [signature[i:i + 8] for i in range(0, 32, 8)]
    # Convert each part to little-endian format
    little_endian_parts = []
    for part in parts:
        temp = ""
        little_endian = part[::-1] # Revert It
        for j in range(0,len(little_endian),2): # For every hex digit
            temp += little_endian[j+1] + little_endian[j] # Make it little endian
        little_endian_parts.append(temp) 
    A = int(little_endian_parts[0],16)
    B = int(little_endian_parts[1],16)
    C = int(little_endian_parts[2],16)
    D = int(little_endian_parts[3],16)
    return A,B,C,D

def New(known:bytes,append:bytes,key_length:int,block_size,message_size_bytes,endian):
    # Re-create the same padded message as the server
    current_message_after_padding = known + b"\x80" + b"\x00" * ((block_size - len(known) - key_length - 1 - message_size_bytes) % block_size) + ((key_length + len(known)) * 8).to_bytes(message_size_bytes,byteorder=endian)
    # Append the extra data
    new_message =  current_message_after_padding + append
    # Calculate the new bit-byte length
    total_prefix = (key_length + len(current_message_after_padding) + len(append)) * 8
    # Create the same padded message that the server will process with the given hash
    to_hash = append + b"\x80" + b"\x00" * ((block_size - len(append) - 1 - message_size_bytes) % block_size) + (total_prefix).to_bytes(message_size_bytes,byteorder=endian)
    
    return new_message,to_hash

def result(new_m,new_s):
    print(f"""
    \t+------------------------++------------------------+
    \t|                   New Message                    |
    \t+------------------------++------------------------+\n""")
    print("\t" + new_m)
    print(f"""\n\t+------------------------++------------------------+
    \t|                   New Signature                  |
    \t+------------------------++------------------------+
    \n\t{new_s}
    """)



def my_tool_args():
    parser = argparse.ArgumentParser(description="Hash Length Extender by eid3t1c")

    parser.add_argument(
        "-f", help=" Hash function used for the signature [MD4,MD5,SHA1,SHA256,SHA512]", type=str
    )
    parser.add_argument(
        "-s", help=" The signature of the message", type=str
    )
    parser.add_argument(
        "-d", help=" Known data used in the signature", type=str, default=""
    )
    parser.add_argument(
        "-e",help=" The desired data to be appended", type=str
    )
    parser.add_argument(
        "-k",help=" The byte length of the key that was used to produce the signature", type=int
    )

    return parser.parse_args()


text = r"""
██╗░░██╗░█████╗░░██████╗██╗░░██╗  ███████╗██╗░░██╗████████╗███████╗███╗░░██╗██████╗░███████╗██████╗░
██║░░██║██╔══██╗██╔════╝██║░░██║  ██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝████╗░██║██╔══██╗██╔════╝██╔══██╗
███████║███████║╚█████╗░███████║  █████╗░░░╚███╔╝░░░░██║░░░█████╗░░██╔██╗██║██║░░██║█████╗░░██████╔╝
██╔══██║██╔══██║░╚═══██╗██╔══██║  ██╔══╝░░░██╔██╗░░░░██║░░░██╔══╝░░██║╚████║██║░░██║██╔══╝░░██╔══██╗
██║░░██║██║░░██║██████╔╝██║░░██║  ███████╗██╔╝╚██╗░░░██║░░░███████╗██║░╚███║██████╔╝███████╗██║░░██║
╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝  ╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝
"""

def main():
    print('\n****************************************************************************************************')
    print(text)
    print('****************************************************************************************************\n')
    arguments = my_tool_args()
    if not (arguments.f or arguments.s or arguments.e or arguments.k):
        Hfunction = input('Select Hash Function >  ')
        Signature = input('Insert Signature >  ')
        Data = input('Insert Known Data [Leave Empty if None] >  ').encode()
        Append = input('Insert Extra Data >  ').encode()
        try:
            Key_length = int(input('Insert Key Length >  '))
        except:
            return print("Please insert only integers !")
    elif not (arguments.f and arguments.s and arguments.e and arguments.k):
        print("Some of the required arguments (-f, -sg, -ed, -kl) are missing. Please provide all of them.")
        return  
    else:
        Hfunction = arguments.f
        Signature = arguments.s
        Data = arguments.d.encode()
        Append = arguments.e.encode()
        Key_length = arguments.k
    if Hfunction == "MD4":
        try:
            new_message,to_hash = New(Data,Append,Key_length,64,8,"little") # Create the new message.
            state = Lendian_STATE(Signature) # split the given hash into a proper state
            new_hash = MD4.MD4(to_hash,state) # Hash the new message with the given hash being the state
            result(str(new_message)[2:-1],new_hash)
        except ValueError as e:
            print(e)
    elif Hfunction == "MD5":
        try:
            new_message,to_hash = New(Data,Append,Key_length,64,8,"little") # Create the new message.
            A,B,C,D = Lendian_STATE(Signature) # split the given hash into a proper state
            new_hash = MD5.MD5(to_hash,(A,B,C,D)) # Hash the new message with the given hash being the state
            result(str(new_message)[2:-1],new_hash)
        except ValueError as e:
            print(e)
    elif Hfunction == "SHA1":
            try:
                new_message,to_hash = New(Data,Append,Key_length,64,8,"big") # Create the new message.
                new_state = Bendian_STATE(Signature,40,5) # split the given hash into a proper state
                new_hash = SHA1.sha1(to_hash,new_state) # Hash the new message with the given hash being the state
                result(str(new_message)[2:-1],new_hash)
            except ValueError as e:
                print(e)
    elif Hfunction == "SHA256":
            try:
                new_message,to_hash = New(Data,Append,Key_length,64,8,"big") # Create the new message.
                new_state = Bendian_STATE(Signature,64,8) # split the given hash into a proper state
                new_hash = SHA256.sha256(to_hash,new_state) # Hash the new message with the given hash being the state
                result(str(new_message)[2:-1],new_hash)
            except ValueError as e:
                print(e)
    elif Hfunction == "SHA512":
            try:
                new_message,to_hash = New(Data,Append,Key_length,128,16,"big") # Create the new message.
                new_state = Bendian_STATE(Signature,128,8) # split the given hash into a proper state
                new_hash = SHA512.sha512(to_hash,new_state) # Hash the new message with the given hash being the state
                result(str(new_message)[2:-1],new_hash)
            except ValueError as e:
                print(e)
    else:
        print("Available Hash Functions -> [MD4, MD5, SHA1, SHA256, SHA512]")
        
            
if __name__ == "__main__":
    main()