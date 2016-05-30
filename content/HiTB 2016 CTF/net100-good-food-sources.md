Title: net100 - Good Food Sources
Date: 2016-05-30 09:57
Author: doskop
Tags: CTF

## Introduction

> Shopping for ingredients is a true challenge and often requires
> going to several shops and distributors. We have recorded one of
> our resident Chefs' routine shopping streaks. Can you discover
> which dish he prepared?
>
> You can get the recording here: [download]({filename}/downloads/hitb-2016-ctf/net100/hitb_03c5e9da492b6f0b71c0bb0dc76323be3b452eafa61629d0dccf5b5da590390c.pcap)

[TL;DR]({filename}/downloads/hitb-2016-ctf/net100/extract.py)

## Analysis

We get a pcap file which shows traffic from a client (10.0.0.3) communicating with two glusterfs servers (10.0.0.1 and 10.0.0.2). Having never dealt with the glusterfs protocol (and not particularly caring about it either), instead of going on a google frenzy I looked at the protocol. It seems to be a relatively protocol where VFS ops are just RPC calls. To create a new file, you call the CREATE function and then call the WRITE function for each chunk. Now, there are two difficulties here. First: The WRITE calls are larger than a single TCP packet so we'll need to reassemble those. Second: It's a cluster filesystem and data gets written in a striped fashion to two different servers in chunks of 131072 bytes so we'll have to adjust for that.

## Exploitation

I decided to use [pynids](https://jon.oberheide.org/pynids/) since one of it's strong points is reassembling fragmented TCP/IP streams. Feeding the pcap file to pynids allows us to concatenate all the data from the client to the server (although pynids seems to think the client is the server) and then just parse (or skip) each RPC call in those streams and emulate the calls we're interested in.

First of all, some preamble to get everything we need imported and set up:

	:::python
    from __future__ import print_function
    import nids
    import sys
    from pwny import *
    target.arch = Target.Arch.unknown
    target.endian = Target.Endian.big

Next, we initialise nids and tell it to feed streams in the pcap file into a handler function:

	:::python
    if len(sys.argv) != 2:
        print('Usage: %s <pcap>' % sys.argv[0], file=sys.stderr)
        sys.exit(1)

	# Set up nids.
    nids.param("scan_num_hosts", 0)         # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
    nids.param('filename', sys.argv[1])
    nids.init()

    # Run stream through the handler.
    print('Parsing stream.. Please wait..')
    nids.register_tcp(handle_tcp_stream)
    nids.run()


The handler function is pretty simple. We're only interested in packets from the client to the server so we collect those and when the stream is finished we feed it to our glusterfs rpc parser:

	:::python
    end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    def handle_tcp_stream(tcp):
        if tcp.nids_state == nids.NIDS_JUST_EST:
            # We only care about the 'server' stream.
            tcp.server.collect = 1
        elif tcp.nids_state == nids.NIDS_DATA:
            tcp.discard(0)
        elif tcp.nids_state in end_states:
            # We pass each individual stream to handle_gluster_stream.
            handle_gluster_stream(tcp.server.data[:tcp.server.count])

Now the hard part. We need to parse all RPC call fragments, combine them into RPC calls where necessary, parse their headers, check if we're interested in this particular call and process it.

We're only interested in the CREATE and WRITE calls. When a new file is created, we track the GFID (a GUID unique for this file), the filename and the stripe index. When data is written, we check which stripe is written in the stream for that particular file and add it to a global dictionary.

	:::python
    # Total set of data to write. Dictionary key should be filename,
    # content a list of (stripe, offset, data) tuples.
    files = {}


    def handle_gluster_stream(data):
        # Parse the collected data from a single stream of glusterfs client-server communication.

        # The packet data.
        pkt = b''

        # Files opened in this stream. Maps GFID to (filename, stripe).
        local_files = {}

        while data:
            frag_data, frag_last, data = parse_frag(data)
            pkt += frag_data
            if not frag_last:
                continue

            # Parse the RPC header.
            xid, pkt = parse_int(pkt)
            mtype, pkt = parse_int(pkt)
            rpc_ver, pkt = parse_int(pkt)
            program, pkt = parse_int(pkt)
            program_ver, pkt = parse_int(pkt)
            procedure, pkt = parse_int(pkt)
            creds_flavor, creds, pkt = parse_creds(pkt)
            verifier_flavor, verifier, pkt = parse_verifier(pkt)

			# Handle file creation. Register filename + stripe.
			if program_ver == 330 and procedure == 23:
                guid, pkt = parse_guid(pkt)
                flags, pkt = parse_int(pkt)
                mode, pkt = parse_int(pkt)
                umask, pkt = parse_int(pkt)
                fn, pkt = parse_str(pkt)
                d, pkt = parse_dict(pkt)
                stripe_index = int(d['trusted.gv0-stripe-0.stripe-index'].rstrip('\x00'))
                gfid = d['gfid-req']
                local_files[gfid] = (fn, stripe_index)
                files.setdefault(fn, [])

			# Write data. Use GFID to determine filename + stripe.
			elif program_ver == 330 and procedure == 13:
                gfid, pkt = parse_guid(pkt)
                fd, pkt = parse_long(pkt)
                offset, pkt = parse_long(pkt)
                chunk_size, pkt = parse_int(pkt)
                flags, pkt = parse_int(pkt)
                d, pkt = parse_dict(pkt)
                fn, stripe_index = local_files[gfid]
                files[fn].append((stripe_index, offset, pkt))

            pkt = b''

Now that we have all chunks for all files, we sort them by `(offset, stripe)` and write them to a file on disk.

	:::python
    # Write chunks to disk. Sort by (offset, stripe).
    for filename, chunks in files.items():
        print('Writing', filename)
        with open(filename, 'wb') as f:
            for stripe, offset, data in sorted(chunks, key=lambda c: (c[1], c[0])):
                f.write(data)

Running this script on the provided pcap leaves us with 2 files: _Crushing typewriter with hydraulic press-kZxIbE7RnhQ.mp4.part_ and _data.tar.gz_. If we extract *data.tar.gz* we'll find a *flag.txt*.