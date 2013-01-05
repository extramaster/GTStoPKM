#!/usr/bin/env python
#============================== CREDITS ==============================
# Original Ruby Plan: https://github.com/jshield/RubyGTS/, Credit: jshield
# Python Implementation Credit: http://projectpokemon.org/forums/showthread.php?21130-Code-GTS-Encryption-Decryption-Library, Credit: K-Shadow 
# GTS format to .pkm file code: http://code.google.com/p/ir-gts/wiki/Readme, Credit: Infinite Recursion
# IR-GTS Python Basic Translation: http://projectpokemon.org/forums/member.php?27134-bpk59, Credit: bpkelley59
#============================== License ==============================
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#============================== INCLUDES ==============================

import socket, sys, time, thread
from sys import *
from platform import system
import os, re, hashlib
from struct import *
from base64 import *
from binascii import *
from array import array
import itertools

#============================== FUNCTIONS ==============================

def decode_data(data):
    b64dec = urlsafe_b64decode(data)
    data_ar = array('B')
    data_ar.fromstring(b64dec)
    checksum = (eval('0x' + hexlify(data_ar[0:4]))) ^ 0x4a3b2c1d
    dec = data_ar[4:len(data_ar)]
    out = array('B')
    rng = checksum | (checksum << 16) & 0x7fffffff
    for i in range(len(dec)):
        rng = (rng * 0x45 + 0x1111) & 0x7fffffff
        key = (rng >> 16) & 0xff
        out.append((dec[i] ^ key) & 0xff)
    return hexlify(out.tostring())

def calcchk(data):
    check = 0
    data_chr = [data[x:x+2] for x in xrange(0,len(data),2)]
    data_r = array('B')
    for x in data_chr:
        data_r.append(eval('0x'+x+''))
    for x in data_r:
        check = check + x
    return check

def encode_data(data):
    chk = calcchk(data)
    appendchk = hex(chk ^ 0x4a3b2c1d)[2:]
    data_chr = [data[x:x+2] for x in xrange(0,len(data),2)]
    data_ar = array('B')
    out = array('B')
    for x in data_chr:
        data_ar.append(eval('0x'+x+''))
    rng = chk | (chk << 16) & 0x7fffffff
    for i in range(len(data_ar)):
        rng = (rng * 0x45 + 0x1111) & 0x7fffffff
        key = (rng >> 16) & 0xff
        out.append((data_ar[i] ^ key) & 0xff)
    outstring = "".join(out.tostring())
    outstr = unhexlify(appendchk) + outstring
    return urlsafe_b64encode(outstr)

shiftind='\x00\x01\x02\x03\x00\x01\x03\x02\x00\x02\x01\x03\x00\x02\x03\x01\x00\x03\x01\x02\x00\x03\x02\x01\x01\x00\x02\x03\x01\x00\x03\x02\x01\x02\x00\x03\x01\x02\x03\x00\x01\x03\x00\x02\x01\x03\x02\x00\x02\x00\x01\x03\x02\x00\x03\x01\x02\x01\x00\x03\x02\x01\x03\x00\x02\x03\x00\x01\x02\x03\x01\x00\x03\x00\x01\x02\x03\x00\x02\x01\x03\x01\x00\x02\x03\x01\x02\x00\x03\x02\x00\x01\x03\x02\x01\x00'

class makerand:
    def __init__(self, rngseed):
      self.rngseed=rngseed
    def rand(self):
      self.rngseed=0x41C64E6D * self.rngseed + 0x6073
      self.rngseed&=0xFFFFFFFF
      return self.rngseed>>16
    __call__=rand

def encode(pkm):
    s=list(unpack("IHH"+"H"*(len(pkm)/2-4), pkm))
    shift=((s[0]>>0xD & 0x1F) %24)
    order=[ord(i) for i in shiftind[4*shift:4*shift+4]]
    shifted=s[:3]
    for i in order: shifted+=s[3+16*i:19+16*i]
    shifted+=s[67:]

    rand=makerand(s[2])
    for i in range(3, 67): shifted[i]^=rand()
    if len(shifted)>67:
      rand=makerand(shifted[0])
      for i in range(67, len(shifted)): shifted[i]^=rand()
    return pack("IHH"+"H"*(len(pkm)/2-4), *shifted)

def decode(bin):
    shifted=list(unpack("IHH"+"H"*(len(bin)/2-4), bin))
    rand=makerand(shifted[2])
    for i in range(3, 67): shifted[i]^=rand()
    if len(shifted)>67:
      rand=makerand(shifted[0])
      for i in range(67, len(shifted)): shifted[i]^=rand()
    shift=((shifted[0]>>0xD & 0x1F) %24)
    order=[ord(i) for i in shiftind[4*shift:4*shift+4]]
    s=shifted[:3]
    for i in range(4): s+=shifted[3+16*order.index(i):19+16*order.index(i)]
    s+=shifted[67:]
    return pack("IHH"+"H"*(len(bin)/2-4), *s)

def prep_pkm( pkm_file ):
      global pkm
      if (len(pkm_file) == 0) or (pkm_file == 'NONE') :
          print 'Enter the path or drag the pkm file here:'
          path = raw_input().strip()
      else:
          path = pkm_file.strip()
      path = os.path.normpath(path)
      if system() != 'Windows':
          path = path.replace('\\', '')
      if path.startswith('"') or path.startswith("'"):
          path = path[1:]
      if path.endswith('"') or path.endswith("'"):
          path = path[:-1]
      print 'Original File at ' + path
      file = open(path, "rb")
      path2 = path.replace('.pkm','') + "_phase1"
      print 'Now writing temporary file to '+path2
      file2 = open(path2, "wb")
      file2.write(a2b_hex(decode_data(file.read())))
      file.close()
      file2.close()

      f = open(path2, 'rb')
      pkm = f.read()
      f.close()
      
      pkm = decode(pkm)
      if len(pkm) != 136:
  	pkm = pkm[0:136]
      pkm_file = path2
      new_pkm_file_name = pkm_file + '.decodedFinal.pkm'
      print "Writing new pkm file:",new_pkm_file_name
      new_pkm_fh = open ( new_pkm_file_name, 'wb' )
      new_pkm_fh.write(pkm)
      new_pkm_fh.close()

#============================== MASTER ==============================

if (len(sys.argv) > 1) and (len(argv[1]) != 0):
    prep_pkm(argv[1])
else:
    prep_pkm ('NONE')
exit(0)

#============================== README ==============================
# How to use?
# Well, grab the network data from your computer while you're using the recieve feature of any
# fakeGTS servers out there, and find a request which looks like the following:
# GET /pokemondpds/worldexchange/post.asp?pid=[PID]&hash=[HASH]&data=[DATA]
#
# Copy and paste everything from [DATA] and save it to a file, it should be in a base64 URL
# encoded format:
#
# Example: SjtWrwDenEDdV4Jy2ZqFjYoQWR_cONZuCCn2seSeXv3_3yvSPcerG1M9mU5KgrJCV4uipn68T_n30DTB71SA2P7Mfur1Z8psmuogAopyhnr0iXaEdUTqDO1ko2mXWAJK3K1nQSiAmvlqxpD0FsBq1BYW9q4QNR4jBbvJnbO6TEiHdwBqkNbE8ANkbjS6FngNcFDs-GG4a23qVmXDlp_fas28c1LBH9_mhsxlkdMOZ4AAt-cdZ-bpsuxWrHuSQtlaGGYWpMVYJQqaUVq82fbVRkTBc2Ay5XwxvnGuaK-sDefWztlWxwuo7-MsjFYekzZ2F3zvqEeFpBo2fXKvV5ft9UiareSfBxt1vf-7hf1Yu45k_7-lrJHUtZM1cPt3Q-HBP_1lYBEYbnPE_PxX
#
# Save that data to a file, launch the script and drag that file to the script, and press enter/return
#
# From there you should get a nice .pkm file from an ugly network string..
#
#============================== END ==============================