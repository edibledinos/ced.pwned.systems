Title: for100 - Secret Recipe
Author: dsc
Date: 2016-06-02 20:12
Tags: CTF

## Introduction

This is a write-up for the for100 challenge of the HiTB 2016 CTF.

> Some customers complained over the phone over not being able to access the Culinary Tour de Force's website.
> They got a strange message and couldn't make a reservation.
> 
> We think the sever might be hacked, but we are not sure, we are chef's not investigators.
> You have access to this image <linkand our packet capture <link>.
> 
> The chef stored his secret recipe encrypted on this server, we don't know if the attacker stole the recipe.
Could you check if his secrets are safe?

> Image file [here]({filename}/downloads/hitb-2016-ctf/ad30567ce980735e8c316f87b02e1235.img.xz). Pcap file [here]({filename}/downloads/hitb-2016-ctf/bin100/77590fce7ccc8a8b335bdcfb121e362a.pcap)

## Analysis

The pcap provided contains a combination of HTTPs and SSH traffic.  

The image provided is a complete dump of a hard disk, which `fdisk` identified as `OpenBSD`.

	$ fdisk -lu recipe.img
    Disk recipe.img: 5368 MB, 5368709120 bytes
    255 heads, 63 sectors/track, 652 cylinders, total 10485760 sectors
    Units = sectors of 1 * 512 = 512 bytes
    Sector size (logical/physical): 512 bytes / 512 bytes
    I/O size (minimum/optimal): 512 bytes / 512 bytes
    Disk identifier: 0x00000000
    
         Device    Boot  Start  End       Blocks   Id  System
    recipe.img4    *     64	    10474379  5237158  a6  OpenBSD

## Mounting
	
We proceeded by mounting the image with an offset of 32768 (sectors are 512 bytes, 512*64)

    mount -o ro,loop,offset=32768,ufstype=44bsd recipe.img mnt1

And got ourselves a partition to gasp at:
	
	$ cd mnt1
    $ ls -al mnt1
    total 17752
    drwxr-xr-x 13 root root  512 Apr 30 13:39 .
    drwxr-xr-x  3 dsc  dsc  4096 Jun  2 19:47 ..
    -rw-r--r--  1 root root  578 Feb 26 09:07 .cshrc
    -rw-r--r--  1 root root  468 Feb 26 09:07 .profile
    drwxr-xr-x  2 root root  512 Feb 26 09:07 altroot
    drwxr-xr-x  2 root root 1024 Feb 26 09:07 bin
    -rw-r--r--  1 root root70964 Apr 30 13:39 boot
    -rw-r--r--  1 root root 10245097 Apr 30 15:38 bsd
    -rw-r--r--  1 root root  7763412 Apr 30 15:38 bsd.rd
    drwxr-xr-x  3 root root19456 May 21 16:15 dev
    drwxr-xr-x 26 root root 1536 May 21 16:15 etc
    drwxr-xr-x  2 root root  512 Apr 30 15:38 home
    drwxr-xr-x  2 root root  512 Feb 26 09:07 mnt
    drwx------  3 root root  512 May 21 16:15 root
    drwxr-xr-x  2 root root 1536 Feb 26 09:08 sbin
    lrwxr-xr-x  1 root root   11 Feb 26 09:07 sys -> usr/src/sys
    drwxrwxrwt  6 root root  512 May 21 16:15 tmp
    drwxr-xr-x  2 root root  512 Apr 30 15:38 usr
    drwxr-xr-x 23 root root  512 Apr 30 14:56 var

First thing we noticed is that /home is empty which confused us. Perhaps this was removed by *the attacker*. Fortunately the `/root` folder has some files:

    $ ls -al root/
    total 24
    drwx------  3 root root  512 May 21 16:15 .
    drwxr-xr-x 13 root root  512 Apr 30 13:39 ..
    -rw-r--r--  1 root root   87 Feb 26 09:07 .Xdefaults
    -rw-r--r--  1 root root  578 Feb 26 09:07 .cshrc
    -rw-r--r--  1 root root   94 Feb 26 09:07 .cvsrc
    -rw-r--r--  1 root root5 Apr 30 13:39 .forward
    drwx------  4 root root  512 Apr 30 16:31 .gnupg
    -rw-r--r--  1 root root  328 Feb 26 09:07 .login
    -rw-------  1 root root 2267 May 21 16:08 .mysql_history
    -rw-r--r--  1 root root  536 Apr 30 13:50 .profile
    -rwxr-xr-x  1 root root   78 Apr 30 13:46 source.sh

Of which 2 entries are interesting: `.gnupg` and `.mysql_history`

Looking at `~/root/.mysql_history` we can notice:

    show tables;
    select * from recipe;
    INSERT INTO recipe (id, name,difficulty,FLAG) VALUES (1, 'whipped cream',1,'HITBCTF{FAKEFAKE}');

Unfortunately no easy flag to be found here :-) It does give an impression that perhaps a flag was once stored in the MySQL database.

Looking at `~/root/.gnupg/` we can see 2 private keys, in a legacy format that was unknown to us (and still is). We tried loading these 2 private keys into a local `gpg` configuration but it wouldn't load them:

    $ gpg --allow-secret-key-import --import 433A76576CCB381536E5602AFF8FAF9DF7CD6F93.key 
    gpg: no valid OpenPGP data found.
    gpg: Total number processed: 0

I was stuck.


## Disk Labels

Our oldest team member [doskop](https://ced.pwned.systems/author/doskop.html) most certainly knows about the existence of disk labels but I sure did not, and as such missed the fact OpenBSD disks are quite different from *traditional* partitions.

Lets see what Wikipedia has to say:

    a disklabel is a record stored on a data storage device such 
	as a hard disk that contains information about the location 
	of the partitions on the disk

We gave the tool [Sleuthkit](http://www.sleuthkit.org/autopsy/features.php) a try, as it claims to have [UFS](https://en.wikipedia.org/wiki/Unix_File_System) support. 

We found our image having multiple disk labels:



    $ apt-get install sleuthkit
	$ mmls -o 64 recipe.img 
	BSD Disk Label
	Offset Sector: 64
	Units are in 512-byte sectors
	
	     Slot    Start        End          Length       Description
	00:  02      0000000000   0010485759   0010485760   Unused (0x00)
	01:  Meta    0000000001   0000000001   0000000001   Partition Table
	02:  00      0000000064   0001953663   0001953600   4.2BSD (0x07)
	03:  01      0001953664   0002477951   0000524288   Swap (0x01)
	04:  03      0002477952   0008769407   0006291456   4.2BSD (0x07)
	05:  04      0008769408   0010474335   0001704928   4.2BSD (0x07)
	06:  -----   0010474336   0010485759   0000011424   Unallocated


Calculate the offsets for the starting point of the 2 remaining disk labels and mount them:

    # Slot 03: 2477952 * 512 = 1268711424
    # Slot 04: 8769408 * 512 = 4489936896

	mount -o ro,loop,offset=1268711424,ufstype=44bsd recipe.img mnt2
    mount -o ro,loop,offset=4489936896,ufstype=44bsd recipe.img mnt3

## Getting somewhere

We spot a directory called `chef` in the last disk label. This probably is the home folder we were missing in our first attempt at mounting the disk.

    $ ls -LR mnt3/
    mnt3:
    chef
    
    mnt3/chef:
    recipe.txt
    
    mnt3/chef/recipe.txt:
    recipe.txt  secret.txt

`/chef/recipe.txt/secret.txt` and `/chef/recipe.txt/recipe.txt` sure do look interesting...

    $ cat recipe.txt 
    -----BEGIN PGP MESSAGE-----
    Version: GnuPG v1
    
    hQEMA3j1+8PfYUh9AQf/aUOPv6hY3kSWgCzfibmluHwupA8TSw3UcM+nw35wpmKR
    kHl6fNQh0cXW1OncAAYAKIGdoa2x1mdVAlhy0RZ8wbi4z1TIqntrkVTjSmriUqAD
    G9E+0WGzhcS3P0Sw7+Y8+AJC6LJB/K2EyUbOyZvxhJ2uM/vinhD/6m0FwUg1lwFy
    I4Z4iabYrv5U7bEOb3upWVAleDIA2aUydHdFw89bV8TWaPpIvuZYpYXxW7h5Krqt
    mzEwAOuBUrVH+IYqEeOfH5JXr8Oucx5w3TqbDXpZ13hOBqxb2VDS8B6qywocp4vQ
    awMhjO9KEFZZFq6/nC6jw3I5f/jmCEvZQ2RMr62mF9JsAcI02uzQnTvWx7EAaKnk
    l7MshpbzLUO7uOtg5ZXZzYX3oOIjKHErI8Wovx7DxDSQnxmASQAtVIwYbWmhykbO
    uNVBI8xxuH283Q0RFcPNKcWsbqYPZPf8nFBXA5eh3rXXX4TZL/ar5+bV3ty+
    =BvJc
    -----END PGP MESSAGE-----
    
    $ cat secret.txt 
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    Version: GnuPG v2
    
    lQPGBFckny0BCADAakIt0wLzRbpOH4u7Fl0vIk4c7XS4l5T6cx7uVvUl+yUyxo3Y
    2mdZDKma+NN2YDHHX3jORkURim4ikMEMTorfeTTiMsoNDeEgPHRofCkyziW6c5FY
    [truncated]
    -----END PGP PRIVATE KEY BLOCK-----

An encrypted message and a private key, how convenient! We import the private key into our local gpg instance.

	$ gpg --allow-secret-key-import --import secret.txt 
	gpg: key 30B0AAD3: secret key imported
	gpg: key 30B0AAD3: public key "chef1 (secret_recipe)" imported
	gpg: Total number processed: 1
	gpg:               imported: 1  (RSA: 1)
	gpg:       secret keys read: 1
	gpg:   secret keys imported: 1

And try to decrypt the message.

	$ gpg recipe.txt 
	
	You need a passphrase to unlock the secret key for
	user: "chef1 (secret_recipe)"
	2048-bit RSA key, ID DF61487D, created 2016-04-30 (main key ID 30B0AAD3)

Oh god. The key is password protected. Well, lets try to bruteforce it.
	
	# fetch random password list
    $ wget "https://github.com/danielmiessler/SecLists/raw/master/Passwords/rockyou.txt.tar.gz"
	$ tar zxvf rockyou.txt.tar.gz

	# fetch/install john-the-ripper community edition
	$ wget "http://www.openwall.com/john/j/john-1.8.0-jumbo-1.tar.gz"
	$ tar zxvf john-1.8.0-jumbo-1.tar.gz
	$ cd $_/src
	$ ./configure
	$ make
	$ cd ../run
	
	# crack
	$ ./gpg2john ../../mnt3/chef/recipe.txt/secret.txt > secret.hash
	$ ./john --wordlist=../../rockyou.txt secret.hash
	Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
	Will run 4 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	footycake123     (chef1)
	1g 0:00:00:49 DONE (2016-06-02 21:25) 0.02022g/s 36354p/s 36354c/s 36354C/s ford1043..foot67

Password `footycake123` has been recovered. Lets try it on `recipe.txt`.

	$ gpg recipe.txt 
	
	You need a passphrase to unlock the secret key for
	user: "chef1 (secret_recipe)"
	2048-bit RSA key, ID DF61487D, created 2016-04-30 (main key ID 30B0AAD3)
	
	gpg: encrypted with 2048-bit RSA key, ID DF61487D, created 2016-04-30
	      "chef1 (secret_recipe)"
	gpg: recipe.txt: unknown suffix
	Enter new filename [recipe.txt]: /tmp/flag.txt

And we `cat` the flag.

	$ cat /tmp/flag.txt
	HITB{41af1026de8e38de54830b0583d7ca08}
