# **Length_Extender**

An automated tool implementing Hash Length Extension attack on ```MD4```,```MD5```,```SHA1```,```SHA256``` and ```SHA512```

# Help Menu

```bash 
Python Length_Extender.py -h
```
Or **if installed with pip**
```cmd 
lenext -h
``` 


![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/b8d1d81f-6444-4e8f-b673-fe1bf321df40)

# Usage

## With arguments

```cmd
python Length_Extender.py -f SHA1 -s efb6be6e9ae5ff61092e409427d44a7fa4f4cc23  -d secret -e admin=True -k 40
``` 
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/f7c7b696-10c1-4dcf-8957-76fbcafdeb8e)



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
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/3f2c4d36-8f7b-44d6-83c2-155f0ea7e2f8)

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
![image](https://github.com/eid3t1c/Length_Extender/assets/102302619/4de43125-d49e-4d19-92e5-ba5f3ade27a5)

