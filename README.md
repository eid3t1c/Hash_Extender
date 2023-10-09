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


