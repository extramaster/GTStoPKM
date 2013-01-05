#!/usr/bin/env python
#============================== CREDITS ==============================
# Original Ruby Plan: https://github.com/jshield/RubyGTS/, Credit: jshield
# Python Implementation Credit: http://projectpokemon.org/forums/showthread.php?21130-Code-GTS-Encryption-Decryption-Library, Credit: K-Shadow 
# GTS format to .pkm file code: http://code.google.com/p/ir-gts/wiki/Readme, Credit: Infinite Recursion
# IR-GTS Python Basic Translation: http://projectpokemon.org/forums/showthread.php?15558-curl-amp-GTS-emulation-convert-336-byte-response-into-220-byte-PKM-file, Credit: bpkelley59
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

import sys
from platform import system
from struct import *
from base64 import *
from binascii import *
from array import array
import itertools
import os
import re
import hashlib
import struct


#============================== FUNCTIONS ==============================


def decode_data(bytes):
    bytes = b64decode(bytes.replace('-', '+').replace('_', '/'))
    ar = array('B')
    ar.fromstring(bytes)
    chksm = (eval('0x' + hexlify(ar[0:4]))) ^ 0x4a3b2c1d
    bin = ar[4:len(ar)]
    pkm = array('B')
    GRNG = chksm | (chksm << 16)
    for i in range(len(bin)):
        GRNG = (GRNG * 0x45 + 0x1111) & 0x7fffffff
        keybyte = (GRNG >> 16) & 0xff
        pkm.append((bin[i] ^ keybyte) & 0xff)
    pkm = pkm[4:len(pkm)]
    pkm = pkm[0:292]
    return pkm

class makerand:
    def __init__(self, rngseed):
      self.rngseed=rngseed
    def rand(self):
      self.rngseed=0x41C64E6D * self.rngseed + 0x6073
      self.rngseed&=0xFFFFFFFF
      return self.rngseed>>16
    __call__=rand

shiftind='\x00\x01\x02\x03\x00\x01\x03\x02\x00\x02\x01\x03\x00\x02\x03\x01\x00\x03\x01\x02\x00\x03\x02\x01\x01\x00\x02\x03\x01\x00\x03\x02\x01\x02\x00\x03\x01\x02\x03\x00\x01\x03\x00\x02\x01\x03\x02\x00\x02\x00\x01\x03\x02\x00\x03\x01\x02\x01\x00\x03\x02\x01\x03\x00\x02\x03\x00\x01\x02\x03\x01\x00\x03\x00\x01\x02\x03\x00\x02\x01\x03\x01\x00\x02\x03\x01\x02\x00\x03\x02\x00\x01\x03\x02\x01\x00'

def decode(bin):
  shifted=list(struct.unpack("IHH"+"H"*(len(bin)/2-4), bin))
  rand=makerand(shifted[2])
  for i in range(3, 67): shifted[i]^=rand()
  if len(shifted)>67:
    rand=makerand(shifted[0])
    for i in range(67, len(shifted)): shifted[i]^=rand()
  
  shift=((shifted[0]>>0xD & 0x1F) %24)
  print shift
  order=[ord(i) for i in shiftind[4*shift:4*shift+4]]
  s=shifted[:3]
  for i in range(4): s+=shifted[3+16*order.index(i):19+16*order.index(i)]
  s+=shifted[67:]
  return struct.pack("IHH"+"H"*(len(bin)/2-4), *s)


def prep_pkm(pkm_file):
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
      file2.write(decode_data(file.read()))
      file.close()
      file2.close()

      with open(path2, 'rb') as f:
          pkm = f.read()
      f.close()
      
      #print pkm
      pkm = decode(pkm)
      #print pkm
      if len(pkm) != 136:
  	pkm = pkm[0:136]
      new_pkm_file_name = path2 + '.decodedFinal.pkm'
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
# Note, this script is currently only tested on the 4th Generation of Pokemon 
# [Pokemon diamond/pearl] ans so is largerly incompatiable with newer generations such as
# Pokemon black
#
#============================== END ==============================