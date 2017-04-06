Title: Awstats Info Leak
Author: dsc
Date: 2017-03-7 11:12
Tags: advisory, exploits

## Advisory

"AWStats is an open source Web analytics reporting tool, suitable for analyzing data from Internet services such as websites."

Some system administrators allow access to Awstats log files:

    inurl:/awstats/data/ filetype:txt inurl:com
    
Awstats log files include visitor stats:

- Visited web paths
- Referer / User-Agent 
- IP addresses
- Error logs

From these we can discover:

- Sensitive files / directories on the webserver
- Sensitive files / directories in the referrer header
- Webserver error logs may reveal PHP bugs

### awstats.py

To automate the  process of parsing large Awstats log files, use [awstats.py](https://github.com/skftn/awstats.py/).

    :::bash
	$ python awstats.py awstats012016.example.com.txt 

	awstats log inspection on awstats042013.example.com.txt

	[*] Searching for interesting access logs
	[password] /Licensing2/secret_password.html
	[password] /Licensing1/secret_password.html
	[*] Finished

use the `--ref` flag to find interesting 'Referer' header values.