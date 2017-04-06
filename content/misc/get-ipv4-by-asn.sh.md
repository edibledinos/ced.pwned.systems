Title: get-ipv4-by-asn.sh
Author: dsc
Date: 2017-1-7 11:10
Tags: reconnaissance, bash
Slug: get-ipv4-by-asn-sh

Which ipv4 addresses belong to a given ASN? Use the following script:


    :::bash
    #!/bin/bash
    for asn in AS51468 AS37061 AS198810 AS39513; 
        do $(for range in $(echo $(whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9.]+){4}/[0-9]+") | sed ':a;N;$!ba;s/\n/ /g'); 
            do prips $range >> ipv4.out; 
        done); 
    done
 
- Requires: `apt-get install prips`
- Results will be appended to `ipv4.out`
- [Github Gist](https://gist.github.com/skftn/6d98bcad533855b1b81b7fdd4e04930e)

