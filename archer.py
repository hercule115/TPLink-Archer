#!/usr/bin/env python

# Tool to update the DDNS record for the ARCHER MR600 router
# It uses the Selenium package to get the IP Address (public) of the router
# and the noipy package to update the DDNS record at No-IP

LOCALTEST = False #True

if LOCALTEST:
    ee = "010001"
    nn = "DFBBDEAD2BC700A78318BDBB7CE5EE22E2199CFF32EFAF4A067B2474817B00AE5A589A8EB7D194EE7321B3147994E871804A1250C91463196F992446A66640AB"
    seq = "643618060"
    aesIv  = 1606831300864752
    aesKey = 1606831300864655

    # hash: "03d3a147236e224ad42b1945cc8323e1"

import builtins as __builtin__
import inspect
import os
import math
import socket
import sys
import random
import time
import getpass
import argparse

import requests
from bs4 import BeautifulSoup
import hashlib

import config	# Shared global config variables (DEBUG,...)

# My private AES crypto
import MyAESCrypto

DEFAULT_HOSTNAME = '192.168.1.1'
HOSTNAME = ''
USERNAME = 'admin'
PASSWORD = ''
LOGFILE = ''

class MyXcryptor():
    def __init__(self, nn, ee, seq):
        self.nn = nn
        self.ee = ee
        self._seq = int(seq)
        self._aesKeyString = ''
        self._hash = ''

        myprint('Creating AES instance')
        self.aes = MyAESCrypto.MyAES()
        self.rsa = MyRSA(self.nn, self.ee)
        
    def setHash(self, name , password):
        self._hash = hashlib.md5(str(name+password).encode('utf-8')).hexdigest()
        myprint('self._hash=',self._hash)
        
    def getHash(self):
        return self._hash
    
    def setHashString(self, hashString):
        self._hash = hashString

    def setSeq(self, seq):
        self._seq = parseInt(seq)
        
    def getSeq(self):
        return self._seq

    def genAESKey(self):
        self.aes.genKey()
        self._aesKeyString = self.aes.getKeyString()
        myprint('self._aesKeyString=',self._aesKeyString)

    def getAESKey(self):
        return self.aes.getKeyString()
    
    def setAESStringKey(self, string):
        self._aesKeyString = string
        self.aes.setStringKey(string)

    def setRSAKey(self, nn, ee):
        self.rsa.setKey(nn, ee)

    def setRSAStringKey(string):
        self.rsa.setStringKey(string)

    def getRSAKey():
        return self.rsa.getKeyString()

    def _getSignature(self, seq, isLogin):
        if 1 == isLogin:
            s = self._aesKeyString + "&h=" + self._hash + "&s=" + str(seq or self._seq)
        else:
            s = "h=" + self._hash + "&s=" + str(seq or self._seq)
        myprint('s=',s)
        return self.rsa.encrypt(s, None, None)

    #VM:151
    def AESEncrypt(self, data, isLogin):
        result = dict()
        result['data'] = self.aes.encrypt(data)
        dataLen = len(result['data'])
        result['sign'] = self._getSignature(self._seq + dataLen, isLogin)
        myprint("result['data']=", result['data'])
        myprint("result['sign']=", result['sign'])
        return result

    def AESDecrypt(self, data):
        return self.aes.decrypt(data)

class MyRSA():
    def __init__(self, nn, ee):
        self.nn = nn
        self.ee = ee

    #encrypt.js: 174
    def _genBI_RC(self):
        BI_RC = dict()

        for vv in range(10):
            BI_RC[ord("0") + vv] = vv

        rr = 0
        for vv in range(10, 36):
            BI_RC[ord("a") + rr] = vv
            rr += 1

        rr = 0
        for vv in range(10, 36):
            BI_RC[ord("A") + rr] = vv
            rr += 1
        #myprint(BI_RC)
        return BI_RC
    
    def _rsaEncrypt(self, data, nn, ee, rsaBits, flag):
        #myprint(data,nn,ee,rsaBits,flag)
        
        self.dbits = 28
        self.DB = self.dbits
        self.DM = (1 << self.dbits) - 1
        self.DV = 1 << self.dbits
        self.FV = math.pow(2, 52)
        self.F1 = 52 - self.dbits
        self.F2 = 2 * self.dbits - 52
        self.BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz"
        self.BI_RC = self._genBI_RC()

        BI_ZERO = self._nbv(0)
        BI_ONE  = self._nbv(1)

        #
        # Skip initialization of rng_pool... (not used)
        #
        STR_EN_LEN = int(rsaBits / 4)
        STR_DE_LEN = int(rsaBits / 8)
        STR_DE_LEN_11PADDING = int(STR_DE_LEN) - 11
        step = STR_DE_LEN_11PADDING if flag else STR_DE_LEN
        startlength = 0
        endlength = step
        tmpen = ""

        #myprint(STR_EN_LEN, STR_DE_LEN,STR_DE_LEN_11PADDING,step)
    
        while startlength < len(data):
            if endlength < len(data) :
                endlength = endlength
            else:
                endlength = len(data)

            #myprint('Calling: calculateRsaValue(%s, %d, %d)' % (data[startlength : endlength], STR_EN_LEN, flag))
        
            tmpen += self._calculateRsaValue(data[startlength : endlength], STR_EN_LEN, flag)
            startlength += step
            endlength += step
        return tmpen
        
    #encrypt.js: 253
    def _fromInt(self, d, x):
        d['t'] = 1
        d['s'] = -1 if x < 0 else 0
        if x > 0:
            d[0] = x
        elif x < -1:
            d[0] = x + DV
        else:
            d['t'] = 0 
        return d

    #encrypt.js: 13
    def _intAt(self, s, i):
        try:
            c = self.BI_RC[ord(s[i])]
        except:
            c = -1
        return c

    def _clamp(self, d):
        c = d['s'] & self.DM
        while d['t'] > 0 and d[d['t'] - 1] == c:
            d['t'] = d['t'] - 1

    def _fromNumber(self, a,b,c):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD TBD ')
        sys.exit(1)

    def _toRadix(self, this, x):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD')
        sys.exit(1)
        return 0

    # Parse a string or a dict. Encode it and return result in a dict
    def _fromString(self, plainText, b):
        myTab = dict()
      
        k = 0
        if 16 == b:
            k = 4
        elif 8 == b:
            k = 3
        elif 256 == b:
            k = 8
        elif 2 == b:
            k = 1
        elif 32 == b:
            k = 5
        elif 4 != b:
            myprint("TBD TBD TBD TBD TBD TBD TBD TBD ")
            sys.exit(1)            #return void this.fromRadix(s, b)
        else:
            k = 2

        t = 0
        s = 0
        mi = False
        sh = 0
        i = len(plainText) - 1
      
        while i >= 0:
            if k == 8:
                x = plainText[i]
            else:
                x = self._intAt(plainText,i)

            #print(i,plainText[i],x,sh,mi)
            
            if x < 0:
                if "-" == plainText[i]:
                    mi = True
            else:
                mi = False
                if sh == 0:
                    myTab[t] = x
                    #myprint('0:',i,plainText[i],x,sh,mi,t,myTab[t])
                    t += 1
                else:
                    if sh + k > self.DB:
                        myTab[t-1] |= (x & (1 << self.DB - sh) - 1) << sh
                        myTab[t] = x >> self.DB - sh
                        #myprint('1:',i,plainText[i],x,sh,mi,t,myTab[t-1],myTab[t])
                        t += 1
                    else:
                        myTab[t-1] |= x << sh
                        #myprint('2:',i,plainText[i],x,sh,mi,'myTab[%d]=%d' % (t-1,myTab[t-1]))
            sh += k
            if sh >= self.DB:
                sh -= self.DB
            i -= 1

        myTab['t'] = t
        myTab['s'] = s    
        
        if k == 8:
            if 128 & plainText[0]:
                myTab['s'] = -1
                if sh > 0:
                    myTab[myTab['t'] - 1] |= (1 << self.DB - sh) - 1 << sh
        self._clamp(myTab)
        if mi:
            myprint("TBD TBD TBD: BigInteger.ZERO.subTo(this, this)")

        myprint('tab=',myTab)
        return myTab

    #encrypt.js: 479
    def _toString(self, this, b):
        #myprint('this=',this)
        if this['s'] < 0:
            x = self._negate(this)
            y = self._toString(x, b)
            return "-" + y

        if 16 == b:
            k = 4
        elif 8 == b:
            k = 3
        elif 2 == b:
            k = 1
        elif 32 == b:
            k = 5
        elif 4 != b:
            return self._toRadix(this, b)
        else:
            k = 2

        d = 0
        km = (1 << k) - 1
        m = False
        r = ""
        i = this['t']
        p = self.DB - i * self.DB % k

        #myprint(d,km,m,r,i,p)

        if i > 0:
            i -= 1
            if p < self.DB:
                d = this[i] >> p
                if d > 0:
                    m = True
                    r = self._int2char(d)
            while i >= 0:
                #myprint(p,k,d,i,m,r)
                if p < k:
                    d = (this[i] & (1 << p) - 1) << k - p
                    i -= 1
                    p += self.DB - k
                    d |= this[i] >> p
                else:
                    p -= k
                    d = this[i] >> p & km
                    if p <= 0:
                        p += self.DB
                        i -= 1
                if d > 0:
                    m = True
                if m:
                    r += self._int2char(d)
        if m:
            myprint('r=',r)
            return r
        else:
            return "0"

    def _nbi(self, a):
        return self._BigInteger(a,None,None)

    #encrypt.js: 17
    def _nbv(self, i):
        d = self._nbi(None)	# new empty dict
        return self._fromInt(d, i)

    #encrypt.js: 5
    def _BigInteger(self, a,b,c):
        if not a:
            return dict()
        elif 'int' in str(type(a)):
            return self._fromNumber(a,b,c)
        elif not b and ('str' in str(type(a)) or 'dict' in str(type(a))):
            return self._fromString(a,256)
        else:
            return self._fromString(a,b)

    # Parse a string and return a dict
    #encrypt.js: 76
    def _parseBigInt(self, s, base):
        return self._BigInteger(s, base, None)

    def _parseInt(self, s, base):
        return int(s, base)

    #encrypt.js: 608
    def _setPublic(self, N, E):
        if not N or not E:
            myprint("Invalid RSA public key")
        self.n = self._parseBigInt(N, 16)
        self.e = self._parseInt(E, 16)
        #myprint('self.n=', self.n, 'self.e=', self.e)

    def _pkcs1pad2(self, s, n):
        myprint('TBD TBD TBD TBD TBD TBD TBD ')

    #encrypt.js: 109
    def _nopadding(self, s, n):
        #myprint('s=',s,'n=',n)
        if n < len(s):
            myprint("Message too long for RSA")
            return None

        ba = dict()
        i = 0
        j = 0
        while i < len(s) and j < n:
            c = ord(s[i])
            i += 1
            if c < 128:
                ba[j] = c
                j += 1
            elif c > 127 and c < 2048:
                ba[j] = 63 & c | 128
                j += 1
                ba[j] = c >> 6 | 192
                j += 1
            else:
                ba[j] = 63 & c | 128
                j += 1
                ba[j] = c >> 6 & 63 | 128
                j += 1
                ba[j] = c >> 12 | 224
                j += 1
        while j < n:
            ba[j] = 0
            j += 1
        #myprint('ba=',ba)
        biba = self._BigInteger(ba, None, None)	# use base = 256
        return biba
        
    def _nbits(self, x):
        return x.bit_length()
       
    #encrypt.js: 532
    def _protoBitLength(self, d):
        t = d['t']
        if t <= 0:
            r = 0
        else:
            r = (self.DB * (t - 1)) + self._nbits(d[t - 1] ^ d['s'] & self.DM)
        return r

    #encrypt.js: 546
    def _isEven(self, d):
        if d['t'] > 0 :
            v = 1 & d[0]
        else:
            v = d['s']
        return 0 == v        

    #encrypt.js: 345    
    def _subTo(self, this, a, r):	# d == this
        i = 0
        c = 0
        m = min(a['t'], this['t'])
        while i < m:
            c += this[i] - a[i]
            r[i] = c & self.DM
            i += 1
            c >>= self.DB

        if a['t'] < this['t']:
            c -= a['s']
            while i < this['t']:
                c += this[i]
                r[i] = c & self.DM
                i += 1
                c >>= self.DB
            c += this['s']
        else:
            c += this['s']
            while i < a['t']:
                c -= a[i]
                r[i] = c & self.DM
                i += 1
                c >>= self.DB
            c += a['s']
        
        r['s'] = -1 if c < 0 else 0
        if c < -1:
            i += 1
            r[i] = self.DV + c
        else:
            if c > 0:
                i += 1
                r[i] = c
        r['t'] = i
        self._clamp(r)
        #myprint('r=',r)
    
    #encrypt.js: 509    
    def _negate(self, this):
        r = self._nbi(None)
        BI_ZERO = self._nbv(0)
        self._subTo(BI_ZERO, this, r)
        return r
       
    def _aabs(self, this):
        s = this['s']
        if s < 0:
            return negate(this)
        else:
            return this
    
    #encrpyt.js: 443
    def _invDigit(self, d):
        if d['t'] < 1:
            return 0
        x = d[0]
        if 0 == (1 & x):
            return 0

        y = 3 & x
        y = y * (2 - (15 & x) * y) & 15
        y = y * (2 - (255 & x) * y) & 255
        y = y * (2 - ((65535 & x) * y & 65535)) & 65535
        y = y * (2 - x * y % self.DV) % self.DV
        if  y > 0 :
            v = self.DV - y
        else:
            v = -y
        return v

    #encrypt.js: 296    
    def _dlShiftTo(self, this, n, r):	# this == d
        i = this['t'] - 1
        while i >= 0:
            r[i + n] = this[i]
            i -= 1

        i = n - 1
        while i >= 0:
            r[i] = 0
            i -= 1
        r['t'] = this['t'] + n
        r['s'] = this['s']
        return r

    #encrypt.js: 313    
    def _lShiftTo(self, this, n, r): # d == this
        bs  = n % self.DB
        cbs = self.DB - bs
        bm  = (1 << cbs) - 1
        ds  = math.floor(n / self.DB)
        c   = this['s'] << bs & self.DM

        i = this['t'] - 1
        while i >= 0:
            r[i + ds + 1] = this[i] >> cbs | c
            c = (this[i] & bm) << bs
            i -= 1
        i = ds - 1
        while i >= 0:
            r[i] = 0
            i -= 1
        r[ds] = c
        r['t'] = this['t'] + ds + 1
        r['s'] = this['s']
        self._clamp(r)

    #encrypt.js: 306    
    def _drShiftTo(self, this, n, r):
        i = n
        while i < this['t']:
            r[i - n] = this[i]
            i += 1
        
        r['t'] = max(this['t'] - n, 0)
        r['s'] = this['s']
        #myprint('r=',r)

    #encrypt.js: 326
    def _rShiftTo(self, this, n, r):
        r['s'] = this['s']
        ds = math.floor(n / self.DB)
        if ds >= this['t']:
            r['t'] = 0
        else:
            bs = n % self.DB
            cbs = self.DB - bs
            bm = (1 << bs) - 1
            r[0] = this[ds] >> bs
            i = ds + 1
            while i < this['t']:
                r[i - ds - 1] |= (this[i] & bm) << cbs
                r[i - ds] = this[i] >> bs
                i += 1
            
            if bs > 0:
                r[this['t'] - ds - 1] |= (this['s'] & bm) << cbs
            r['t'] = this['t'] - ds
            self._clamp(r)
        #myprint('r=',r)
    
    #encrypt.js: 246    
    def _copyTo(self, d, r):
        i = d['t'] - 1
        while i >= 0:
            r[i] = d[i]
            i -= 1
        r['t'] = d['t']
        r['s'] = d['s']

    #encrypt.js: 519    
    def _compareTo(self, this, a):
        r = this['s'] - a['s']
        if 0 != r:
            return r
        i = this['t']
        r = i - a['t']
        if 0 != r:
            if this['s'] < 0:
                return -r
            else:
                return r
        i -= 1
        while i >= 0:
            r = this[i] - a[i]
            #print(i,r)
            if 0 != r:
                return r
            i -= 1	# DP ADDED 29/12/20
        return 0

    #encrypt.js: 156
    def _am(self, d, i, x, w, j, c, n): # d == this
        xl = 16383 & x
        xh = x >> 14

        n -= 1
        while n >= 0:
            l = 16383 & d[i]
            h = d[i] >> 14
            i += 1
            m = xh * l + h * xl
            l = xl * l + ((16383 & m) << 14) + w[j] + c
            c = (l >> 28) + (m >> 14) + xh * h
            w[j] = 268435455 & l
            j += 1
            n -= 1
        return c
    
    #encrypt.js: 395
    def _divRemTo(self, this, m, q, r):
        pm = self._aabs(m)
        if pm['t'] > 0:
            pt = self._aabs(this)
            if pt['t'] < pm['t']:
                if q:
                    self._fromInt(q, 0)
                    if r:
                        self._copyTo(this, r)
                    return
            if not r:
                r = self._nbi(None)
            y = self._nbi(None)
            ts = this['s']
            ms = m['s']
            nsh = self.DB - self._nbits(pm[pm['t'] - 1])
            if nsh > 0:
                self._lShiftTo(pm, nsh, y)
                self._lShiftTo(pt, nsh, r)
            else:
                self._copyTo(pm, y)
                self._copyTo(pt, r)
                myprint('y=',y)
                myprint('r=',r)

            ys = y['t']
            y0 = y[ys - 1]
            if 0 != y0:
                if ys > 1:
                    yt = y0 * (1 << self.F1) + (y[ys - 2] >> self.F2)
                else:
                    yt = y0 * (1 << self.F1)
                d1 = self.FV / yt
                d2 = (1 << self.F1) / yt
                e = 1 << self.F2
                i = r['t']
                j = i - ys
                if not q:
                    t = self._nbi(None)
                else:
                    t = q

                self._dlShiftTo(y, j, t)
                if self._compareTo(r, t) >= 0:
                    r[r['t']] = 1
                    r['t'] = r['t'] + 1
                    self._subTo(r, t, r)
                BI_ONE = self._nbv(1)
                self._dlShiftTo(BI_ONE, ys, t)
                self._subTo(t, y, y)
                while y['t'] < ys:
                    y[y['t']] = 0 
                    y['t'] = y['t'] + 1

                j -= 1
                while j >= 0:
                    i -= 1
                    if r[i] == y0:
                        qd = self.DM
                    else:
                        qd = math.floor(r[i] * d1 + (r[i - 1] + e) * d2)
                    r[i] += self._am(y, 0, qd, r, j, 0, ys)
                    if r[i]  < qd:
                        self._dlShiftTo(y, j, t)
                        self._subTo(r, t, r)
                        qd -= 1
                        while r[i] < qd:
                            self._subTo(r, t, r)
                        qd -= 1
                    j -= 1

                if None != q:
                    self._drShiftTo(r,ys, q)
                    if ts != ms:
                        BI_ZERO = self._nbv(0)
                        self._subTo(BI_ZERO, q, q)
                r['t'] = ys
                self._clamp(r)
                if nsh > 0:
                    self._rShiftTo(r, nsh, r)
                if ts < 0:
                    BI_ZERO = self._nbv(0)
                    self._subTo(BI_ZERO, r, r)
    
    def _Classic(self, d):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD ')
        return None
    
    #encrypt.js: 39
    def _Montgomery(self, d):
        # Return a 'Montgomery' dict (home made)
        mongo = dict()
        mongo['m']   = d
        mongo['mp']  = x = self._invDigit(d)
        mongo['mpl'] = 32767 & x
        mongo['mph'] = x >> 15
        mongo['um']  = (1 << self.DB - 15) - 1
        mongo['mt2'] = 2 * d['t']
        #myprint(mongo)
        return mongo

    #encrypt.js: 382    
    def _squareTo(self, this, r):
        x = self._aabs(this)
        i = r['t'] = 2 * x['t']
        i -= 1
        while i >= 0:
            r[i] = 0
            i -= 1
        i = 0
        while i <  x['t'] - 1:
            c = self._am(x, i, x[i], r, 2 * i, 0, 1)
            r[i + x['t']] += self._am(x, i + 1, 2 * x[i], r, 2 * i + 1, c, x['t'] - i - 1)
            if r[i + x['t']] >= self.DV:
                r[i + x['t']] -= self.DV
                r[i + x['t'] + 1] = 1
            i += 1
        if r['t'] > 0:
            r[r['t'] - 1] += self._am(x, i, x[i], r, 2 * i, 0, 1)
        r['s'] = 0
        self._clamp(r)
    
    #encrypt.js: 201    
    def _sqrTo(self, this, x, r):
        self._squareTo(x, r)
        self._reduce(this, r)

    #encrypt.js: 369
    def _multiplyTo(self, this, a, r):
        x = self._aabs(this)
        y = self._aabs(a)
        i = x['t']
        r['t'] = i + y['t']
        i -= 1
        while i >= 0:
            r[i] = 0
            i -= 1
        i = 0
        while i < y['t']:
            r[i + x['t']] = self._am(x, 0, y[i], r, i, 0, x['t'])
            i += 1
        r['s'] = 0
        self._clamp(r)
        if this['s'] != a['s']:
            BI_ZERO = self._nbv(0)
            self._subTo(BI_ZERO, r, r)
    
    #encrypt.js: 236
    def _mulTo(self, this, x, y, r):
        self._multiplyTo(x, y, r)
        self._reduce(this, r)

    #encrypt.js: 221
    def _reduce(self, this, x):
        while x['t'] <= this['mt2']:
            x[x['t']] = 0
            x['t'] += 1
        i = 0
        while i < this['m']['t']:
            j = 32767 & x[i]
            u0 = j * this['mpl'] + ((j * this['mph'] + (x[i] >> 15) * this['mpl'] & this['um']) << 15) & self.DM
            j = i + this['m']['t']
            x[j] += self._am(this['m'], 0, u0, x, i, 0, this['m']['t'])
            while x[j] >= self.DV:
                x[j] -= self.DV
                j += 1
                x[j] += 1
            i += 1
        self._clamp(x)
        self._drShiftTo(x, this['m']['t'], x)
        if self._compareTo(x, this['m']) >= 0:
            self._subTo(x, this['m'], x)

    #encrypt.js: 10
    def _int2char(self, n):
        return self.BI_RM[n]
        
    #encrypt.js: 206
    def _convert(self, z, x): # z == this
        m = z['m']
        mt = m['t']
        v = self._aabs(x)
        r = self._nbi(None)
        self._dlShiftTo(v, mt, r)
        self._divRemTo(r, m, None, r)
        if x['s'] < 0:
            BI_ZERO = self._nbv(0)
            if self._compareTo(r, BI_ZERO) > 0:
                self._subTo(z['m'], r, r)
        return r

    #encrypt.js: 214    
    def _revert(self, this, x):
        r = self._nbi(None)
        self._copyTo(x, r)
        self._reduce(this, r)
        return r
    
    #encrypt.js: 460
    def _exp(self, d, e, z):
        if (e > 4294967295 or e < 1):
            #return BigInteger.ONE
            ONE = dict()
            ONE[0] = 1
            ONE['s'] = 0
            ONE['t'] = 1
            return ONE
        r = self._nbi(None)
        r2 = self._nbi(None)
        g = self._convert(z, d)
        i = self._nbits(e) - 1
        self._copyTo(g, r)
        i -= 1
        while i >= 0:
            self._sqrTo(z, r, r2)
            if (e & 1 << i) > 0:
                self._mulTo(z, r2, g, r)
            else:
                t = r
                r = r2
                r2 = t
            
            i -= 1
        v = self._revert(z, r)
        return v
    
    #encrypt.js: 543
    def _modPowInt(self, d, e, m):		# e = ee, m = nn converted to BigInteger
        even = self._isEven(m)
        if e < 256 or even:
            z = self._Classic(m)
        else:
            z = self._Montgomery(m)
            z = self._exp(d, e, z)
        return z
    
    #encrypt.js: 604
    def _doPublic(self, x):
        return self._modPowInt(x, self.e, self.n)
    
    #encrypt.js: 613
    def _encrypt(self, text, flag):
        if flag:
            m = self._pkcs1pad2(text, self._protoBitLength(self.n) + 7 >> 3)
        else:
            m = self._nopadding(text, self._protoBitLength(self.n) + 7 >> 3)
        if m == None:
            return None
        c = self._doPublic(m)
        if c == None:
            return None
        h = self._toString(c, 16)
        if 0 == (1 & len(h)):
            return h
        else:
            return "0" + h
        
    def _calculateRsaValue(self, val, strEnlen, flag):
        self._setPublic(self.nn, self.ee)
        result = self._encrypt(val, flag)
        l = abs(strEnlen - len(result))
        i = 0
        while i < l:
            result = "0" + result
            i += 1
        myprint('result=',result)
        return result
    
    ####
    # Public methods
    #VMxxx: 82
    def encrypt(self, plaintText, nn, ee):
        return self._rsaEncrypt(plaintText, self.nn or nn, self.ee or ee, 512, 0)

####
class Archer:
    def __init__(self, hostName, userName, userPassword, session):
        self._hostName = hostName
        self._name     = userName
        self._password = userPassword
        self._session  = session
        
        self._md5Hash = ''
        self._aesKey  = ''
        self._aesIv   = ''
        self._aesKeyString = ''
        
        self.n = 0 # Public RSA key (from getParm())
        self.e = 0 # Public RSA exponent (from getParm())

        # Request header prototype. Updated with specific request
        self._protoHeaders = {
            'Accept': 		'*/*',
            'Accept-Encoding': 	'gzip, deflate',
            'Accept-Language': 	'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control': 	'no-cache',
            'Connection': 	'keep-alive',
            'Cookie': 		'loginErrorShow=1',
            'Pragma': 		'no-cache',
            'User-Agent': 	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.67 Safari/537.36'
        }
        self._headers = Headers(self._protoHeaders)
        self._headers.setHeader('Host', self._hostName)
        self._headers.setHeader('Referer', 'http://%s/' % (self._hostName))

        # Requests to send with _cgi_gdpr() script
        self._configInfoCgiGdprRqst = dict()
        self._configInfoCgiGdprRqst[0] = "1&1&1&8" + "\r\n" + "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,3" + "\r\n" + "modelName" + "\r\n" + "description" + "\r\n" + "X_TP_IsFD" + "\r\n" + "[ETH_SWITCH#0,0,0,0,0,0#0,0,0,0,0,0]1,1" + "\r\n" + "numberOfVirtualPorts" + "\r\n" + "[SYS_MODE#0,0,0,0,0,0#0,0,0,0,0,0]2,0" + "\r\n" + "[/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0" + "\r\n"

        self._configInfoCgiGdprRqst[1] = "1&1&1" + "\r\n" + "[FW_UPGRADE_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[CLOUD_SERVICE#0,0,0,0,0,0#0,0,0,0,0,0]1,1" + "\r\n" + "tcspStatus" + "\r\n" + "[CURRENT_USER#0,0,0,0,0,0#0,0,0,0,0,0]2,0" + "\r\n"

        self._configInfoCgiGdprRqst[2] = "1&1" + "\r\n" + "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,2" + "\r\n" + "hardwareVersion" + "\r\n" + "softwareVersion" + "\r\n" + "[X_TP_LTE#0,0,0,0,0,0#0,0,0,0,0,0]1,1" + "\r\n" + "IMEI" + "\r\n"

        self._configInfoCgiGdprRqst[3] = "5" + "\r\n" + "[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,8" + "\r\n" + "Enable" + "\r\n" + "BSSID" + "\r\n" + "SSID" + "\r\n" + "X_TP_Band" + "\r\n" + "Channel" + "\r\n" + "AutoChannelEnable" + "\r\n" + "BasicEncryptionModes" + "\r\n" + "BeaconType" + "\r\n"        
        self._configInfoCgiGdprRqst[4] = "6&6&1&1" + "\r\n" + "[LAN_WLAN_MSSIDENTRY#0,0,0,0,0,0#1,1,0,0,0,0]0,3" + "\r\n" + "Name" + "\r\n" + "SSID" + "\r\n" + "Enable" + "\r\n" + "[LAN_WLAN_MSSIDENTRY#0,0,0,0,0,0#1,2,0,0,0,0]1,3" + "\r\n" + "Name" + "\r\n" + "SSID" + "\r\n" + "Enable" + "\r\n" + "[LAN_WLAN_GUESTNET#1,1,0,0,0,0#0,0,0,0,0,0]2,2" + "\r\n" + "Name" + "\r\n" + "Enable" + "\r\n" + "[LAN_WLAN_GUESTNET#1,2,0,0,0,0#0,0,0,0,0,0]3,2" + "\r\n" + "Name" + "\r\n" + "Enable" + "\r\n"

        self._configInfoCgiGdprRqst[5] = "1&5&5&5&1&5&5&1&5" + "\r\n" + "[L3_FORWARDING#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "__ifAliasName" + "\r\n" + "[WAN_IP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]1,3" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "ConnectionType" + "\r\n" + "[WAN_PPP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]2,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[WAN_COMMON_INTF_CFG#0,0,0,0,0,0#0,0,0,0,0,0]3,1" + "\r\n" + "WANAccessType" + "\r\n" + "[L3_IP6_FORWARDING#0,0,0,0,0,0#0,0,0,0,0,0]4,1" + "\r\n" + "__ifAliasName" + "\r\n" + "[WAN_PPTP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]5,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[WAN_L2TP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]6,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[SYS_MODE#0,0,0,0,0,0#0,0,0,0,0,0]7,2" + "\r\n" + "Mode" + "\r\n" + "lteBackupEnable" + "\r\n" + "[WAN_LTE_LINK_CFG#0,0,0,0,0,0#0,0,0,0,0,0]8,0" + "\r\n"

        self._configInfoCgiGdprRqst[6] = "1&2" + "\r\n" + "[LTE_NET_STATUS#2,1,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[ONEMESH_RT#0,0,0,0,0,0#0,0,0,0,0,0]1,1" + "\r\n" + "action=4" + "\r\n"

        self._configInfoCgiGdprRqst[7] = "6&1" + "\r\n" + "[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,2" + "\r\n" + "Enable" + "\r\n" + "X_TP_Band" + "\r\n" + "[HOST_NUM#0,0,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

        self._configInfoCgiGdprRqst[8] = "2" + "\r\n" + "[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "pageNumber=0" + "\r\n"

        self._configInfoCgiGdprRqst[9] = "1" + "\r\n" + "[LTE_SMS_UNREADMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "totalNumber" + "\r\n"

        self._configInfoCgiGdprRqst[10] = "1" + "\r\n" + "[TIME#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "localTimeZone" + "\r\n"

        self._configInfoCgiGdprRqst[11] = "5" + "\r\n" + "[ONEMESH_DEVICE#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"

        #...
        
        self._configInfoCgiGdprRqst[12] = "1&1&1" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[LTE_WAN_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,3" + "\r\n" + "dataSwitchStatus" + "\r\n" + "networkPreferredMode" + "\r\n" + "roamingEnabled" + "\r\n" + "[WAN_LTE_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]2,1" + "\r\n" + "dataLimit" + "\r\n"

        self._configInfoCgiGdprRqst[13] = "1&1&1&1&1" + "\r\n" + "[WAN_COMMON_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[WAN_LTE_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]1,8" + "\r\n" + "dataLimit" + "\r\n" + "enablePaymentDay" + "\r\n" + "curStatistics" + "\r\n" + "totalStatistics" + "\r\n" + "enableDataLimit" + "\r\n" + "limitation" + "\r\n" + "curRxSpeed" + "\r\n" + "curTxSpeed" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]2,0" + "\r\n" + "[LTE_PROF_STAT#2,1,0,0,0,0#0,0,0,0,0,0]3,0" + "\r\n" + "[LTE_NET_STATUS#2,1,0,0,0,0#0,0,0,0,0,0]4,0" + "\r\n"

        self._configInfoCgiGdprRqst[14] = "1" + "\r\n" + "[WAN_IP_CONN#2,1,1,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"

        self._configInfoCgiGdprRqst[15] = "1&1" + "\r\n" + "[DIAG_TOOL#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "LastResult" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

        self._configInfoCgiGdprRqst[16] = "7" + "\r\n" + "[ACT_DIAG_STARTDIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"

        self._configInfoCgiGdprRqst[17] = "1&1" + "\r\n" + "[DIAG_TOOL#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "LastResult" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

        #Scripts used to logout from router
        self._logoutCgiGdprRqst = dict()
        self._logoutCgiGdprRqst[0] = "8" + "\r\n" + "[/cgi/clearBusy#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"
        self._logoutCgiGdprRqst[1] = "8" + "\r\n" + "[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0"  + "\r\n"

        # Script used to reboot the router
        self._rebootCgiGdprRqst = dict()
        self._rebootCgiGdprRqst[0] = "7" + "\r\n" + "[ACT_REBOOT#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"
        
    @property
    def hostname(self):
        return self._hostName

    @property
    def headers(self):
        return self._headers.headers

    def initEncryptor(self):
        if not (hasattr(self, 'nn') and hasattr(self, 'ee') and hasattr(self, 'seq')):
            myprint('self.nn, self.ee, self.seq NOT INITIALIZED')
            sys.exit(1)
        self.encryptor = MyXcryptor(self.nn, self.ee, self.seq)

    # HTTP Requests
    def initialPage(self, doParse):
        url = '%s%s' % ('http://', self._hostName)
        myprint('GET(): %s' % url)
        #myprint('Headers=', self.headers)
        r = self._session.get(url, headers=self.headers)
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)
        if r.status_code != 200:
            return
        #dumpToFile('%s.html' % self._hostName, r.text)
        #myprint('session cookies:',self._session.cookies)
        if doParse:
            soup = BeautifulSoup(r.text, 'html.parser')
            #myprint('head=',soup.head)
            containers = soup.find_all('script', type = 'text/javascript')
            # Search for the token variable
            varName = 'token'
            myprint('Searching for "%s" in index' % varName)
            for i in range(len(containers)):
                text = containers[i].string
                if text == None:
                    continue
                #myprint('text=', text)
                stmt = getJSVarAssignStmt(text, varName)
                if stmt:
                    #myprint('Setting self.%s' % (varName))
                    s = 'self.' + stmt		# self.token="351ffcfd8eb26b59cefb7613173b71"
                    #myprint('exec: %s' % s)
                    exec(s)			# Execute command

            if not (hasattr(self, varName)):
                myprint('Failed to get variable %s' % varName)
            else:
                myprint('%s = %s' % (varName, self.token))
    
    def getParm(self, *argv):
        baseurl = 'http://%s/cgi/getParm' % self._hostName
        
        if len(argv):
            param = '?%s' % (argv[0])
            url = '%s%s' % (baseurl, param)
            myprint('GET(): %s' % url)

            h = self.headers
            h['Accept']       = '*/*'
            h['Content-Type'] = 'text/plain'
            h['TokenID']      = self.token
            myprint('self.headers=',h)
            r = self._session.get(url, headers=h)
        else:
            myprint('POST(): %s' % baseurl)
            h = self.headers
            h['Accept'] = '*/*'
            h['Origin'] = 'http://%s' % (self._hostName)
            myprint('self.headers=',h)
            r = self._session.post(baseurl, headers=h)
            
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)
        if r.status_code == 200:
            if self._parseParm(r.text):
                myprint('ERROR: Fail to parse getParm() response')
                sys.exit(1)
        
    def loadinggif(self):
        url = 'http://%s/img/loading.gif' % self._hostName
        myprint('GET(): %s' % url)

        h = self.headers
        h['Accept'] = 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8'

        r = self._session.get(url, headers=h)
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)

    def getBusy(self):
        url = 'http://%s/cgi/getBusy' % self._hostName
        myprint('POST(): %s' % url)
        r = self._session.post(url, headers=self.headers)
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)
        
        ret = getJSVarAssignStmt(r.text, 'isBusy')
        if ret:
            exec('self.'+ret)
        myprint('isBusy=',self.isBusy)
        return self.isBusy

    # Download a script
    def getScript(self, *argv):
        args = argv[0]
        baseurl = 'http://%s/' % self._hostName
        scriptFamily = args[0]
        scriptName   = args[1]
        url = '%s%s/%s' %(baseurl, scriptFamily, scriptName)
        for i in range(2,len(*argv)):
            url += '?' + args[i]

        myprint('GET(): %s' % url)
        r = self._session.get(url, headers=self.headers)
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)
        if r.status_code == 200:
            if not os.path.isdir(scriptFamily):
                myprint('Creating: %s' % (scriptFamily))
                try:
                    os.makedirs(scriptFamily, exist_ok=True)
                except OSError as e:
                    msg = "Cannot create %s: %s" % (scriptFamily, "{0}".format(e.strerror))
                    myprint(msg)
                    return
            dumpToFile('%s/%s' % (scriptFamily, scriptName), r.text)

    # Download an image/icon
    def getImage(self, *argv):
        args = argv[0]

        baseurl = 'http://%s/' % self._hostName
        scriptFamily = args[0]
        scriptName = args[1]
        url = '%s%s/%s' %(baseurl, scriptFamily, scriptName)
        for i in range(2,len(*argv)):
            url += '?' + args[i]

        myprint('GET(): %s' % url)
        r = self._session.get(url, headers=self.headers)
        myprint('response code:',r.status_code)
        myprint('response headers:',r.headers)
        if r.status_code == 200:
            if not os.path.isdir(scriptFamily):
                myprint('Creating: %s' % (scriptFamily))
                try:
                    os.makedirs(scriptFamily, exist_ok=True)
                except OSError as e:
                    msg = "Cannot create %s: %s" % (scriptFamily, "{0}".format(e.strerror))
                    myprint(msg)
                    return
            dumpToFile('%s/%s' % (scriptFamily, scriptName), r.text)
            
    # index: 1182
    def loginSubmit(self):
        self.encryptor.setHash(self._name, self._password)
        self.encryptor.genAESKey()
        n = self.encryptor.AESEncrypt(self._name + "\n" + self._password, 1)

        if config.LOCALTEST:
            myprint('n=',n)
            sign = "757a9b1bdee5fb31b6cc7ee8ca2f73be8678202f1bd3927ffa795fcc18edb0263a51c37ee6effa223bc737c84126d4c054d9a16d1a5070f5ce533060ab36cce404029f2351e235275e990015f8844eb0fa7d8ebe3bb24de8f81ba26ad1ddac0aaadbb32f86f1930a255458233908048a88c0ab897c9d7e9564c56e37664b8e3c"
            data = 'ZFS0qzA7+rPxgJGDkCamjg=='
            if n['sign'] == sign and n['data'] == data:
                myprint(" TEST OK OK OK OK OK OK OK OK OK OK")
            else:
                myprint("TEST KO KO KO KO KO KO KO KO KO KO")

        # RSA Encrypt password (not used)
        #n = self._rsaEncrypt(b64enc(self._password), self.nn, self.ee)
        #e = self._rsaEncrypt(self._name, self.nn, self.ee) #: rsaEncrypt("admin", $.nn, $.ee))

        # POST login request
        e = userInfo = None
        self._doLogin(e, n, 1, "#pc-login-btn", userInfo)

    # Logout from router
    def logout(self):
        info = dict()
        for i in range(len(self._logoutCgiGdprRqst)):
            self._cgi_gdpr(i, self._logoutCgiGdprRqst[i], info)
        myprint(info)

    def reboot(self):
        self._baseLogin()
        
        info = dict()
        for i in range(len(self._rebootCgiGdprRqst)):
            self._cgi_gdpr(i, self._rebootCgiGdprRqst[i], info)
        myprint(info)
        
    def getConfig(self):
        # assert(self._hostName)
        # assert(self._session)
        # assert(self._name)
        # assert(self._password)

        # myprint("*** Connecting to:", self._hostName, " ***")
        
        # self.initialPage(0)
        # self.getParm()
        
        # # We got self.nn, self.ee, self.seq from previous request,
        # # Now, create Encryptor instance
        # myprint('Creating encryptor')
        # self.initEncryptor()

        # # Mimic behavior
        # self.loadinggif()

        # isBusy = self.getBusy()
        # if isBusy:
        #     myprint('*** WARNING: isBusy is set ***')
        
        # # Connect with credentials
        # self.loginSubmit()
        
        # # Reload main page and parse output to get the token
        # self.initialPage(1)

        # # Load various scripts one by one
        # for script in (
        #         ('css', 'main.css'),
        #         ('css', 'tpTable.css'),
        #         ('css', 'pure-min.css'),
        #         ('css', 'jquery.tp.min.css'),
        #         ('css', 'simple-slider.css'),
        #         ('js',  'jquery-1.8.3.min.js'),
        #         ('js',  'oid_str.js'),
        #         ('locale/en_US', 'str.js'),
        #         ('locale/en_US', 'help.js'),
        #         ('locale/en_US', 'array.js'),
        #         ('locale/en_US', 'err.js'),
        #         ('locale/en_US', 'lan.css'),
        #         ('js',  'proxy.js'),
        #         ('js',  'encrypt.js'),
        #         ('js',  'lib.js'),
        #         ('js',  'wireless.js'),
        #         ('js',  'keycode.js'),
        #         ('js',  'simple-slider.js'),
        #         ('js',  'corner.js'),
        #         ('js',  'jquery.tp.min.js'),
        #         ('js',  'excanvas.js'),
        #         ('js',  'Chart.js'),
        #         ('js',  'su.js'),
        #         ('js',  'isp.js'),
        #         ('locale', 'language.js', '_=%d' % int(time.time() * 1e3)),
        #         ('locale', 'locale.js', '_=%d' % int(time.time() * 1e3)),
        #         ('js', 'cryptoJS.min.js', '_=%d' % int(time.time() * 1e3)),
        #         ('js', 'tpEncrypt.js', '_=%d' % int(time.time() * 1e3))
        # ):
        #     #self.getScript(script)
        #     myprint('Skipping download:', script)

        # # Load various images one by one
        # for img in (
        #         ('img', 'globalLoading.gif'),
        #         ('img', 'icons.png')
        # ):
        #     #self.getImage(img)
        #     myprint('Skipping download:', img)
                
        # #self.getBusy()

        # # Re-read parameters using a GET
        # qstring = "_=%d" % int(time.time() * 1e3)
        # self.getParm(qstring)

        # Logon the router, load initial page, create encryptor...
        self._baseLogin()
        
        # Real work. get config information from router
        info = self._getConfigInfo()

        # Parse raw output and store config in configInfo{}
        configInfo = parseCgiGdprInfo(info)
        return configInfo

    def _baseLogin(self):
        assert(self._hostName)
        assert(self._session)
        assert(self._name)
        assert(self._password)

        myprint("*** Connecting to:", self._hostName, " ***")
        
        self.initialPage(0)
        self.getParm()
        
        # We got self.nn, self.ee, self.seq from previous request,
        # Now, create Encryptor instance
        myprint('Creating encryptor')
        self.initEncryptor()

        # Mimic behavior
        self.loadinggif()

        isBusy = self.getBusy()
        if isBusy:
            myprint('*** WARNING: isBusy is set ***')
        
        # Connect with credentials
        self.loginSubmit()
        
        # Reload main page and parse output to get the token
        self.initialPage(1)

        # Load various scripts one by one
        for script in (
                ('css', 'main.css'),
                ('css', 'tpTable.css'),
                ('css', 'pure-min.css'),
                ('css', 'jquery.tp.min.css'),
                ('css', 'simple-slider.css'),
                ('js',  'jquery-1.8.3.min.js'),
                ('js',  'oid_str.js'),
                ('locale/en_US', 'str.js'),
                ('locale/en_US', 'help.js'),
                ('locale/en_US', 'array.js'),
                ('locale/en_US', 'err.js'),
                ('locale/en_US', 'lan.css'),
                ('js',  'proxy.js'),
                ('js',  'encrypt.js'),
                ('js',  'lib.js'),
                ('js',  'wireless.js'),
                ('js',  'keycode.js'),
                ('js',  'simple-slider.js'),
                ('js',  'corner.js'),
                ('js',  'jquery.tp.min.js'),
                ('js',  'excanvas.js'),
                ('js',  'Chart.js'),
                ('js',  'su.js'),
                ('js',  'isp.js'),
                ('locale', 'language.js', '_=%d' % int(time.time() * 1e3)),
                ('locale', 'locale.js', '_=%d' % int(time.time() * 1e3)),
                ('js', 'cryptoJS.min.js', '_=%d' % int(time.time() * 1e3)),
                ('js', 'tpEncrypt.js', '_=%d' % int(time.time() * 1e3))
        ):
            #self.getScript(script)
            myprint('Skipping download:', script)

        # Load various images one by one
        for img in (
                ('img', 'globalLoading.gif'),
                ('img', 'icons.png')
        ):
            #self.getImage(img)
            myprint('Skipping download:', img)
                
        #self.getBusy()

        # Re-read parameters using a GET
        qstring = "_=%d" % int(time.time() * 1e3)
        self.getParm(qstring)

    def _getConfigInfo(self):
        info = dict()
        for i in range(len(self._configInfoCgiGdprRqst)):
            # Collect configuration information using cgi_gdpr HTTP requests,
            # store information in info{}
            self._cgi_gdpr(i, self._configInfoCgiGdprRqst[i], info)
        return info
        
    def _cgi_gdpr(self, rqstNo, rqstStr, result):
        myprint('rqstNo=%d, rqstStr=%s' %(rqstNo, rqstStr))
        
        # AES Encrypt the request
        payload = self.encryptor.AESEncrypt(rqstStr, 0)

        # Format the data 
        d = "sign=" + payload['sign'] + "\r\ndata=" + payload['data'] + "\r\n"
        myprint('data=', d)
        
        url = 'http://%s/cgi_gdpr' % self._hostName
        myprint('POST(): %s' % url)

        h = self.headers
        h['Accept']         = '*/*'
        h['Origin']         = 'http://%s' % (self._hostName)
        h['Content-Type']   = 'text/plain'
        h['Content-Length'] = str(len(d))
        h['TokenID']        = self.token

        r = self._session.post(url, headers=h, data=d)
        myprint('response code:',r.status_code)
        if r.status_code != 200:
            myprint('Reason:', r.reason)
            sys.exit(1)
        myprint('response headers:',r.headers)

        v = self.encryptor.AESDecrypt(r.text)
        myprint('Decrypted response text=',v)
        result[rqstNo] = v

    # Parse getParm() response. Initialize nn,ee,seq variables used by RSA encryptor
    def _parseParm(self, s):
        global LOCALTEST
        global ee, nn, seq

        #myprint('Parsing: %s' % s)

        info = ''
        if hasattr(self, 'nn'):
            info = 'self.nn= %s ' % self.nn
        if hasattr(self, 'ee'):
            info += 'self.ee= %s ' % self.ee
        if hasattr(self, 'seq'):
            info += 'self.seq = %s' % self.seq
        if info:
            myprint('Current values:', info)
            
        if LOCALTEST:
            myprint('WARNING: Using hardcoded values')
            self.nn = nn
            self.ee = ee
            self.seq = seq
            return 0
        
        vars = s.split(';')
        if len(vars) < 3:
            myprint('Invalid getParm() response %s' % s)
            return -1

        for var in vars:
            try:
                #myprint('var=',var)
                v = var.split(' ')[1]	# ee="010001"
                w = 'self.'+v		# self.ee="010001"
                #myprint('exec: %s' % w)
                exec(w)			# Execute command
            except:
                myprint('Skipping %s' % var)

        if not (hasattr(self, 'nn') and hasattr(self, 'ee') and hasattr(self, 'seq')):
            return -1
        myprint('nn=%s ee=%s seq=%s' % (self.nn,self.ee,self.seq))
        return 0

    def _doLogin(self, e, n, action, btn, userInfo):
        baseurl = 'http://%s/' % self._hostName
        script = 'cgi/login'
        sep1 = '?data='
        data = n['data'].replace('=', '%3D').replace('+', '%2B')
        sep2 = '&sign='
        sign = n['sign']
        trailer = '&Action=1&LoginStatus=0'

        url = '%s%s%s%s%s%s%s' % (baseurl, script, sep1, data, sep2, sign,trailer)
        myprint('POST(): %s' % url)
        r = self._session.post(url, headers=self.headers)
        myprint('response code:',r.status_code)
        if r.status_code != 200:
            myprint('Login failed. code: %d' % r.status_code)
            sys.exit(1)

        cookieHdr = self._headers.getHeader('Cookie')
        myprint('Cookie Header=',cookieHdr)

        # Parse Response Headers and update generic headers with new cookies
        myprint('Response cookies=',r.cookies)
        rHdr = Headers(r.headers)
        rCookieHdr = rHdr.getHeader('Set-Cookie')
        jSessionId = getCookie(rCookieHdr, 'JSESSIONID')
        newCookieHdr = cookieHdr + "; " + jSessionId
        self._headers.setHeader('Cookie', newCookieHdr)
        myprint('self._headers', self.headers)

#### Class Headers
class Headers():
    def __init__(self, d):
        self._h = d

    @property
    def headers(self):
        return self._h

    def setHeader(self, hdr, val):
        self._h[hdr] = val

    # Return header value if found
    def getHeader(self, hdr):
        try:
            val = self._h[hdr]
        except:
            return None
        return val
    
    def getCookie(self, cookie):
        for k,v in self._h.items():
            if k == 'Set-Cookie':
                cookies = v.split(';')
                for c in cookies:
                    try:
                        cc = c.split('=')
                    except:
                        myprint('Skipping %s' % cc)
                        continue
                    if cc[0] == cookie:
                        return cc[1]
        return None
        
####        
def module_path(local_function):
    ''' returns the module path without the use of __file__.  
    Requires a function defined locally in the module.
    from http://stackoverflow.com/questions/729583/getting-file-path-of-imported-module'''
    return os.path.abspath(inspect.getsourcefile(local_function))

def myprint(*args, **kwargs):
    """My custom print() function."""
    # Adding new arguments to the print function signature 
    # is probably a bad idea.
    # Instead consider testing if custom argument keywords
    # are present in kwargs

    class color:
        PURPLE    = '\033[95m'
        CYAN      = '\033[96m'
        DARKCYAN  = '\033[36m'
        BLUE      = '\033[94m'
        GREEN     = '\033[92m'
        YELLOW    = '\033[93m'
        RED       = '\033[91m'
        BOLD      = '\033[1m'
        UNDERLINE = '\033[4m'
        END = '\033[0m'

    if config.DEBUG:
        __builtin__.print('%s%s()%s:' % (color.BOLD, inspect.stack()[1][3], color.END), *args, **kwargs)

def utf8Parse(t):
    r = len(str(t))
    tAsString = str(t)
    e = dict()
    i = 0
    while i < r:
        try:
            x = e[i >> 2]
        except:
            e[i >> 2] = 0
            
        e[i >> 2] |= (255 & ord(tAsString[i])) << 24 - i % 4 * 8
        i += 1
    return e

def dumpToFile(fname, plainText):
    try:
        myprint('Creating %s' % fname)
        out = open(fname, 'w')
        out.write(plainText)
        out.close()
    except IOError as e:
        msg = "I/O error: Creating %s: %s" % (fname, "({0}): {1}".format(e.errno, e.strerror))
        myprint(msg)
        sys.exit(1)

def getCookie(cookieStr, cookie):
    if not cookie in cookieStr:
        return ''

    cookies = cookieStr.split(';')
    for c in cookies:
        if c.startswith(cookie):
            return c
    return ''

def getJSVarAssignStmt(plainText, varName):
    myprint(plainText, varName)
    if plainText == '':
        return ''
    
    if not ';' in plainText:
        plainText += ';'
    try:
        vars = plainText.split(';')
        for var in vars:
            try:
                v = var.split(' ')[1]
                if varName in v:
                    myprint(v)
                    return v
            except:
                myprint('Unable to parse %s' % var)
                continue
    except:
        myprint('ERROR: Parsing %s' % plainText)
        return ''

def parseCgiGdprInfo(infoDict):
    configInfo = dict()
    
    for i in range(len(infoDict)):
        infoString = infoDict[i]
        myprint('i=%d infoString=%s' % (i, infoString))
        infos = infoString.split("\n")
        #myprint('infos=',infos)
        for line in infos:
            #myprint(line)
            if '=' in line:
                #myprint(line)
                parm,value = line.split('=')
                if parm == '$.ret':		# Skip over unwanted fields
                    continue
                if parm.startswith('var '):	# Remove 'var ' prefix
                    parm = parm[4:]
                if value.endswith(';'):		# Remove ';' suffix
                    value = value[:-1]
                # Append value if existing, strip leading ';'
                try:
                    if value in configInfo[parm]:
                        # Duplicate value
                        myprint('val %s already in entry %s' % (value,parm))
                    else:
                        # Add to existing entry
                        configInfo[parm] = (configInfo.get(parm,'') + '; ' + value)
                except:
                    configInfo[parm] = value	# New entry

                # Strip leading '; '
                if configInfo[parm].startswith('; '): configInfo[parm] = configInfo[parm][2:]
                        
    return configInfo

def humanBytes(size):
    power = float(2**10)     # 2**10 = 1024
    n = 0
    power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size = float(size / power)
        n += 1
    return '%s %s' % (('%.2f' % size).rstrip('0').rstrip('.'), power_labels[n])

# Arguments parser
def parse_argv():
    desc = 'Get TP-Link Archer router current configuration, as shown on the first page after login'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-d", "--debug",
                        action="store_true", dest="debug", default=False,
                        help="print debug messages (to stdout)")
    parser.add_argument('-f', '--file',
                        dest='logFile',
                        const=LOGFILE,
                        default=None,
                        action='store',
                        nargs='?',
                        metavar = 'FILE',
                        help="write debug messages to FILE (default to <hostname>-debug.txt)")
    parser.add_argument('--host',
                        dest='hostName',
                        action='store',
                        nargs='?',
                        help="TP-Link Archer router IP address/name (default to %s)" % DEFAULT_HOSTNAME)
    parser.add_argument('-u', '--user',
                        dest='userName',
                        help="Username to use for login (default to %s)" % (USERNAME))
    parser.add_argument('-p', '--password',
                        dest='password',
                        help="Password to use for login")
    parser.add_argument("-i", "--info",
                        action="store_true", dest="version", default=False,
                        help="print version and exit")
    args = parser.parse_args()
    return args

####
def main():
    global USERNAME, PASSWORD

    args = parse_argv()    

    if args.version:
        print('%s: version 1.1' % sys.argv[0])
        sys.exit(0)

    if args.debug:
        config.DEBUG = True

    with requests.session() as session:
        if args.hostName:
            HOSTNAME = args.hostName
        else:
            HOSTNAME = DEFAULT_HOSTNAME
            
        if args.userName:
            USERNAME = args.userName
        if not USERNAME:
            userName = input('Username <Default=admin>:' )
            if not userName:
                userName = 'admin'
            USERNAME = userName

        if args.password:
            PASSWORD = args.password
        if not PASSWORD:
            password = getpass.getpass()
            if not password:
                myprint('Invalid empty password')
                sys.exit(1)
            PASSWORD = password

        if args.logFile == None:
            #print('Using stdout')
            pass
        else:
            if args.logFile == '':
                LOGFILE = "%s-debug.txt" % HOSTNAME
            else:
                LOGFILE = args.logFile
            print('Using log file: %s' % LOGFILE)
            try:
                sys.stdout = open(LOGFILE, "w")
            except:
                print('Cannot create log file')

        # Create instance of router at hostName, connect with given credentials
        archer = Archer(HOSTNAME, USERNAME, PASSWORD, session)

        # Read current configuration
        archerConfig = archer.getConfig()

        # Work done. Logout from router
        archer.logout()

        # Dump configuration
        sd = sorted(archerConfig.items())
        for k,v in sd:
            print("{: <25}: {}".format(k,v))

        modelName  = archerConfig['modelName']
        MACAddress = archerConfig['MACAddress']
        ipv4       = archerConfig['ipv4']

        # get usage statistics
        totalStatistics = int(float(archerConfig['totalStatistics']))
        limitation      = int(archerConfig['limitation'])

        bssid = archerConfig['BSSID'].split('; ')[0]
        print('Hostname: %s, Model: %s, BSSID: %s, IPv4: %s' %(HOSTNAME, modelName, bssid, ipv4))
        #print('BSSID: %s' % archerConfig['BSSID'])
        print('Usage: %s / %s' % (humanBytes(totalStatistics), humanBytes(limitation)))

        if args.logFile and args.logFile != '':
            sys.stdout.close()
        
# Entry point    
if __name__ == "__main__":
    main()
