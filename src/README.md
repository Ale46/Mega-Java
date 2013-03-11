# MegaJava

Java library for the [mega] (mega.co.nz) API, currently supporting:
 - login
 - downloading
 - list directory & files (also if shared from others)
 - add contacts
 
This work is based on source code released by @NT2005.

## Requirements
[Java-json] (http://json.org/java/)

## How to use
Import MegaJava and json library on your project

###Login
```java
MegaHandler mh = new MegaHandler("user@mail.com", "password");
mh.login();
```
###Get user details
```java
mh.get_user()
```
###Get and print user files
```java
ArrayList<MegaFile> mf = mh.get_files();
	for(int i = 0;i<mf.size();i++)
		print(mf.get(i).isDirectory() ? "[DIR]"+mf.get(i).getName() : "[File]"+mf.get(i).getName());
```
###Get and print user files
```java
try {
	mh.download("https://mega.co.nz/#!xVUkCKbY!Aq_5U3HiWTJMEAK7N_5ENGugZVp0bMj9C8JSjgF8zBM", "C:\\Users\\admin\\Desktop");
	} catch (InvalidAlgorithmParameterException e) {
		e.printStackTrace();
	}
```
###Add a contact
```java
mh.add_user("friend@mail.com")
```

