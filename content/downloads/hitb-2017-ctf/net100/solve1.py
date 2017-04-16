#!/usr/bin/env python2
import re,sys,sabyenc

data = open(sys.argv[1], "r").readlines()
files = {}

for i in range(0, len(data)):
    line = data[i]

    if line.startswith("=ybegin"):  # beginning of a new yenc file
        has_offsets = data[i+1].startswith("=ypart")  # check if the second line contains begin/end
        headers = {  # nntp headers
            "begin": 0,
            "end": 0,
            "size": int(re.search('size=(.\d+?) ', line).group(1))
        }

        if not headers['size']:
            raise Exception("could not parse size=")
        if has_offsets:  # try to parse begin/end
            try:
                headers['begin'] = int(re.search('begin=(.\d+?) ', data[i+1]).group(1))
                headers['end'] = int(re.search('end=(.\d+?)\r\n', data[i+1]).group(1))
            except:
                print "warning: begin/end could not be correctly parsed"
        if not headers['begin']:  # sometimes begin turns into None, reset to 0
            headers['begin'] = 0

        # yencode-decoding using sabyenc - input data includes the 1/2 header lines and the trailing '=yend'
        decoded_data, output_filename, crc, crc_yenc, crc_correct = sabyenc.decode_usenet_chunks(
            data[i:], headers['size'])

        if not crc_correct: raise Exception("faulty checksum")
        print "output_filename:", output_filename
        print "size:", headers['size']
        print "decoded_data length:", len(decoded_data)

        if output_filename not in files:
            files[output_filename] = []
        files[output_filename].append({
            "begin": headers['begin'],
            "end": headers['end'],
            "data": decoded_data
        })

print "sorting chunks and writing files."

for output_filename, chunks in files.items():
    chunks = sorted(files[output_filename], key=lambda k: k['begin'])
    data = "".join([chunk["data"] for chunk in chunks])

    open("output/%s" % output_filename, "wb").write(data)
    print "written %s" % output_filename