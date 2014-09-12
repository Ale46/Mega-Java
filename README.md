# MegaJava
[![gittip](https://img.shields.io/gittip/Ale46.svg)](https://www.gratipay.com/Ale46/)

Java library for the [mega.co.nz] (https://mega.co.nz) API, currently supporting:
 - login
 - downloading
 - list directory & files (also if shared from others)
 - get download link
 - add contacts
 - get space left
 
This work is based on the source code released by [@NT2005] (https://github.com/NT2005).

## Requirements
[Java-json] (http://json.org/java/)

## How to use
Import MegaJava and json library on your project

###Login (you need this step before do anything)
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
		System.out.println(mf.get(i).isDirectory() ? "[DIR]"+mf.get(i).getName() : "[File]"+mf.get(i).getName());
```
###Download files from url
```java
try {
  mh.download("https://mega.co.nz/#!xVUkCKbY!Aq_5U3HiWTJMEAK7N_5ENGugZVp0bMj9C8JSjgF8zBM", "C:\\Users\\admin\\Desktop");
} catch (InvalidAlgorithmParameterException e) {
  e.printStackTrace();
}
```
###Get download url (works only against own files)
```java
mh.get_url(MegaFile);
```
###Add a contact
```java
mh.add_user("friend@mail.com")
```
###Get free space (bytes)
```java
mh.get_quota();
```
