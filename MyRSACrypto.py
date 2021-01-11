#!/usr/bin/env python

# Tool to update the DDNS record for the ARCHER MR600 router
# It uses the Selenium package to get the IP Address (public) of the router
# and the noipy package to update the DDNS record at No-IP

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

import hashlib
import binascii

try:
    import config	# Shared global config variables (DEBUG,...)
except:
    print('config.py does not exist. Importing generator')
    import initConfig	# Check / Update / Create config.py module

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
        myprint(BI_RC)
        return BI_RC
    
    def _rsaEncrypt(self, data, nn, ee, rsaBits, flag):
        myprint(data,nn,ee,rsaBits,flag)
        
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

        myprint(STR_EN_LEN, STR_DE_LEN,STR_DE_LEN_11PADDING,step)
    
        while startlength < len(data):
            if endlength < len(data) :
                endlength = endlength
            else:
                endlength = len(data)

            myprint('=> calculateRsaValue(%s, %d, %d)' % (data[startlength : endlength], STR_EN_LEN, flag))
        
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
        print('_fromNumber(): TBD TBD TBD TBD TBD TBD TBD TBD TBD ')
        sys.exit(1)

    def _toRadix(self, this, x):
        print('_toRadix(): TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD')
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
                    myprint('0:',i,plainText[i],x,sh,mi,t,myTab[t])
                    t += 1
                else:
                    if sh + k > self.DB:
                        myTab[t-1] |= (x & (1 << self.DB - sh) - 1) << sh
                        myTab[t] = x >> self.DB - sh
                        myprint('1:',i,plainText[i],x,sh,mi,t,myTab[t-1],myTab[t])
                        t += 1
                    else:
                        myTab[t-1] |= x << sh
                        myprint('2:',i,plainText[i],x,sh,mi,'myTab[%d]=%d' % (t-1,myTab[t-1]))
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
                myprint(p,k,d,i,m,r)
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
        myprint('self.n=', self.n, 'self.e=', self.e)

    def _pkcs1pad2(self, s, n):
        print('_pkcs1pad2(): TBD TBD TBD TBD TBD TBD TBD ')

    #encrypt.js: 109
    def _nopadding(self, s, n):
        myprint('s=',s,'n=',n)
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
        myprint('ba=',ba)
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
        myprint('r=',r)
    
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
        myprint('r=',r)

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
        myprint('r=',r)
    
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
        print('_Classic(): TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD ')
        sys.exit(1)
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
        myprint(mongo)
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
    def _modPowInt(self, d, e, m):		# e = ee, m = nn as BigInteger
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
    def setKey(self, nn, ee):
        self.nn = nn
        self.ee = ee
        
    #VMxxx: 82
    def encrypt(self, plaintText, nn, ee):
        return self._rsaEncrypt(plaintText, self.nn or nn, self.ee or ee, 512, 0)

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
        __builtin__.print('%s%s()%s:' % (color.YELLOW, inspect.stack()[1][3], color.END), *args, **kwargs)
    

# Arguments parser
def parse_argv():
    desc = 'Get TP-Link Archer router current configuration, as shown on the first page after login'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-d", "--debug",
                        action="store_true", dest="debug", default=False,
                        help="print debug messages (to stdout)")
    parser.add_argument('-f', '--file',
                        dest='logFile',
                        const='',
                        default=None,
                        action='store',
                        nargs='?',
                        metavar = 'FILE',
                        help="write debug messages to FILE (default to MyRSACrypto-debug.txt)")
    args = parser.parse_args()
    return args

def main():
    ee = "010001"
    nn = "DFBBDEAD2BC700A78318BDBB7CE5EE22E2199CFF32EFAF4A067B2474817B00AE5A589A8EB7D194EE7321B3147994E871804A1250C91463196F992446A66640AB"
    seq = "643618060"

    args = parse_argv()

    if args.debug:
        config.DEBUG = True
    
    # Text to encrypt
    msg = b'Hello World!!'

    # Encrypted Text
    encCheck = "4b8f80fdcdfef73aa8f6cf0ff054b42f1ac3f2a92aece9ba86efbe0d2a8638204ef5af798928f85baeca778e1b023b16d90dfc22192574323a94fe71856fb986"
    
    rsa = MyRSA(nn, ee)
    encrypted = rsa.encrypt('Hello World!!', None, None)

    print("Crypto Encrypted:", encrypted)
    if encrypted == encCheck:
        print('SUCCESS')
    
# Entry point    
if __name__ == "__main__":
    # Absolute pathname of directory containing this module
    moduleDirPath = os.path.dirname(module_path(main))

    # Check if config module is already imported. If not, build it
    try:
        x = globals()['config']
        haveConfig = True
    except:
        haveConfig = False

    if not haveConfig:
        # Create config.py with Mandatory/Optional fields 
        mandatoryFields = [('b','DEBUG')]
        optionalFields  = [('s','ROUTER_USERNAME'),
                           ('p','ROUTER_PASSWORD'),
                           ('s','ROUTER_HOSTNAME'),
                           ('s','LOGFILE')]
                       
        initConfig.initConfig(moduleDirPath, mandatoryFields, optionalFields)

        # Import generated module
        try:
            import config
        except:
            print('config.py initialization has failed. Exiting')
            sys.exit(1)

    main()
