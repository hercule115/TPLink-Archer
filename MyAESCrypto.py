#!/usr/bin/env python3
#
# This is a simple script to encrypt/decrypt a message using AES
# with CBC mode in Python 3.

import builtins as __builtin__
import inspect

import sys
import math
import time
import random
import argparse

import config

class MyAESCipher:
    def __init__(self, key):
        self.key = str(key)
        myprint('key: %s' % (self.key))

    def encrypt(self, iv, data):
        myprint('iv: %s' % iv)
        self.cipher = MyAES()
        self.cipher.setKey(self.key, iv)
        return self.cipher.encrypt(data)
        
    def decrypt(self, iv, data):
        ivb  = bytes(str(iv), 'utf-8')
        myprint('iv: %s' % iv)
        self.cipher = MyAES()
        self.cipher.setKey(self.key, iv)
        return self.cipher.decrypt(data)

############
class MyAES:
    def __init__(self):
        self._key     = None
        self._iv      = None
        self._keyUtf8 = None
        self._ivUtf8  = None
        self._keyString = ''

        self.ENC_XFORM_MODE = 1
        self.DEC_XFORM_MODE = 2

        self._t = dict()
        self._h = dict()
        self._f = dict()
        self._l = dict()
        self._u = dict()
        self._d = dict()
        self._p = dict()
        self._v = dict()
        self.__ = dict()
        self._y = dict()
        self._g = dict()
    
        self._initthfludpv_yg()

    def getKey(self):
        result = dict()
        result['key'] = self._key
        result['iv']  = self._iv
        return result

    def setKey(self, key, iv):
        if 'str' in str(type(key)) and len(key) == 16:
            self._key = key
            self._keyUtf8 = utf8Parse(self._key)
        if 'str' in str(type(iv)) and len(iv) == 16:
            self._iv  = iv
            self._ivUtf8  = utf8Parse(self._iv)

    def genKey(self):
        self._iv  = int(str(int(time.time() * 1e6) + int(random.random() * 1e3))[0:16])
        self._key = int(str(int(time.time() * 1e6) + int(random.random() * 1e3))[0:16])

        if config.LOCALTEST:
            myprint('WARNING: Using hardcoded values')
            self._iv  = AESIV
            self._key = AESKEY

        self._ivUtf8  = utf8Parse(self._iv)
        self._keyUtf8 = utf8Parse(self._key)
            
        myprint('self._key=',self._key, 'self._iv=',self._iv)
        myprint('self._keyUtf8=',self._keyUtf8, 'self._ivUtf8=',self._ivUtf8)

    def genAESKey(self):
        self.genKey()
        self._keyString = self._aesGetKeyString()

    def getKeyString(self):
        s = 'key=%s&iv=%s' % (self._key, self._iv)
        return s

    def setStringKey(self, string):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD')
        temp = string.split("&")
        key  = temp[0].split("=")[1]
        iv   = temp[1].split("=")[1]
        myprint('key=',key,'iv=',iv)
        self.setKey(key, iv)
        
    class MyDecryptor:
        def __init__(self, parent, key, iv):
            self._parent = parent
            self._key  = key
            self._iv   = iv
            self._xformMode = parent.DEC_XFORM_MODE
            myprint('parent:', parent, 'key: %s iv: %s' % (self._key, self._iv))

            self.this = dict()
            self.this['_iv']  = self._iv
            self.this['_key'] = dict()
            self.this['_key'] = key
            
            self.this['pthis'] = self._parent._this

            self.this['_xformMode'] = self._xformMode
            self.this['_minBufferSize'] = 1
            self.this['blockSize'] = 4
            
            self.this['processBlock'] = self._processBlock
            self.this['decryptBlock'] = self._decryptBlock
            self.this['func_o']       = self._parent._func_o
            
            self.this['formatter'] = dict()
            self.this['formatter']['parse'] = self.parse
            self.this['formatter']['stringify'] = self.stringify
            
            self.this['cfg'] = dict()
            self.this['cfg']['iv'] = iv
            self.this['cfg']['padding'] = dict()
            self.this['cfg']['padding']['pad']   = self._parent._pad
            self.this['cfg']['padding']['unpad'] = self._parent._unpad

            self._parent._reset(self)
            
        #VM: 1137
        def _processBlock(self, t, r):
            e = self.this
            i = e['blockSize']
            myprint('e=',e)
            n = slice(t, r, r + i)
            myprint('e=',e,'i=',i)
            myprint('n=',n)
            e['decryptBlock'](t, r)
            e['func_o'](e, t, r, i)
            self.this['_prevBlock'] = n
            
        def _decryptBlock(self, t, r):
            e = t[r + 1]
            t[r + 1] = t[r + 3]
            t[r + 3] = e

            p = self._parent
            p.doCryptBlock(self.this, t, r, self.this['_invKeySchedule'], p._v, p.__, p._y, p._g, p._f)
            e = t[r + 1]
            t[r + 1] = t[r + 3]
            t[r + 3] = e
            myprint('t=',t)
            
        # VM: 125
        def stringify(self, this):
            t = this['ciphertext']
            #myprint('t=',t)
            r = t['words']
            e = t['sigBytes']
            i = list()
            n = 0
            while n < e:
                o = r[n >> 2] >> 24 - n % 4 * 8 & 255
                i.append(chr(o))
                n += 1
            return "".join(i)

        #VM: 1214
        def parse(self, t, pthis):  # pthis = parent _this
            r = self._parse(pthis, t)
            e = r['words']

            i = dict()        
            if 1398893684 == e[0] and 1701076831 == e[1]:
                i['words'] = slice(e, 2, 4)
                i['sigBytes'] = n if n else 4 * i['length']
                splice(e, 0, 4)
                r['sigBytes'] -= 16
            ret = dict()
            ret['ciphertext'] = r
            ret['salt'] = i
            myprint('ret=',ret)
            return ret
    
        def _parse(self, pthis, t):
            e = _map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            r = len(t)
            try:
                i = pthis['_reverseMap']
            except:
                i = pthis['_reverseMap'] = dict()

                n = 0
                while n < len(e):
                    i[ord(e[n])] = n
                    n += 1
                pthis['_reverseMap'] = i
            
            o = e[64]
            if o:
                s = t.find(o)
                if s != -1:
                    r = s

            ret = self._fun1(t, r, i)
            myprint('ret=',ret)
            return ret

        def _fun1(self, t, r, e):
            i = dict()
            n = 0
            o = 0
            myprint('t=',t)
            myprint('e=',e)
            while o < r:
                if o % 4:
                    s = e[ord(t[o-1])] << o % 4 * 2
                    a = e[ord(t[o])] >> 6 - o % 4 * 2
                    try:
                        i[n >> 2] |= toSigned32((s | a) << 24 - n % 4 * 8)
                    except:
                        i[n >> 2] = toSigned32((s | a) << 24 - n % 4 * 8)
                    #myprint(o,n,s,a,i)
                    n += 1
                o += 1
            i['length'] = len(i)
            myprint('n=',n)
            myprint('i=',i)

            ret = dict()
            ret['words'] = i
            ret['sigBytes'] = n if n else 4 * i['length']
            return ret

    class MyEncryptor:
        def __init__(self, parent, key, iv):
            self._parent = parent
            self._key  = key
            self._iv   = iv
            self._xformMode = parent.ENC_XFORM_MODE
            myprint('parent:', parent, 'key: %s iv: %s' % (self._key, self._iv))

            self.this = dict()
            self.this['pthis'] = self._parent._this
            self.this['cfg'] = dict()
            self.this['cfg']['iv'] = iv
            self.this['cfg']['padding'] = dict()
            self.this['cfg']['padding']['pad'] = self._parent._pad
            self.this['cfg']['padding']['unpad'] = self._parent._unpad
        
            self.this['_key'] = dict()
            self.this['_key'] = key

            self.this['_xformMode'] = self._xformMode
            self.this['_minBufferSize'] = 0
            
            self.this['blockSize'] = 4

            self.this['processBlock'] = self._processBlock
            self.this['encryptBlock'] = self._encryptBlock
            self.this['func_o']       = self._parent._func_o
            
            self._parent._reset(self)

        #VM: 1138
        def _processBlock(self, t, r): # this=_cipher, t=words, r=int
            e = self.this
            i = e['blockSize']
            myprint(e)
            e['func_o'](e, t, r, i)
            e['encryptBlock'](t, r)
            self.this['_prevBlock'] = slice(t, r, r + i)
            myprint('self.this[_prevBlock]=',self.this['_prevBlock'])
            
        #VM: 1701
        def _encryptBlock(self, t, r): # this=_cipher
            myprint(t, r)
            p = self._parent
            p.doCryptBlock(self.this, t, r, self.this['_keySchedule'], p._l, p._u, p._d, p._p, p._h)

    def _initthfludpv_yg(self):
        r = 0
        while r < 256:
            self._t[r] = r << 1 if r < 128 else r << 1 ^ 283
            r += 1
        e = 0
        i = 0
        r = 0
        while r < 256:
            n = i ^ i << 1 ^ i << 2 ^ i << 3 ^ i << 4
            n = n >> 8 ^ 255 & n ^ 99
            self._h[e] = n
        
            self._f[n] = e
            o = self._t[self._f[n]]
            s = self._t[o]
        
            a = self._t[s]
            c = 257 * self._t[n] ^ 16843008 * n
        
            self._l[e] = toSigned32(c << 24 | c >> 8)
            self._u[e] = toSigned32(c << 16 | c >> 16)
            self._d[e] = toSigned32(c << 8 | c >> 24)
        
            self._p[e] = c
                
            c = 16843009 * a ^ 65537 * s ^ 257 * o ^ 16843008 * e
        
            self._v[n] = toSigned32(c << 24 | c >> 8)
            self.__[n] = toSigned32(c << 16 | c >> 16)
            self._y[n] = toSigned32(c << 8 | c >> 24)
            self._g[n] = toSigned32(c)
        
            if e:
                e = o ^ self._t[self._t[self._t[a ^ o]]]
                i ^= self._t[self._t[i]]
            else:
                e = i = 1
        
            r += 1

        self._t['length'] = len(self._t)
        self._h['length'] = len(self._h)
        self._f['length'] = len(self._f)
        self._l['length'] = len(self._l)
        self._u['length'] = len(self._u)
        self._d['length'] = len(self._d)
        self._p['length'] = len(self._p)
        self._v['length'] = len(self._v)
        self.__['length'] = len(self.__)
        self._y['length'] = len(self._y)
        self._g['length'] = len(self._g)

    #VM:1680
    def _doReset(self, xcryptor):
        myprint('xcryptor=', xcryptor)
        w = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

        this = xcryptor.this
        h = self._h
        
        this['keySize'] = 8

        this['_data'] = dict()
        this['_data']['words'] = dict()
        this['_data']['words']['length'] = 0
        this['_data']['sigBytes'] = 0
        
        this['_nDataBytes'] = 0
        this['_nRounds'] = 0
        this['_keyPriorReset'] = dict()
        
        if (this['_nRounds'] != 0 or this['_keyPriorReset'] == this['_key']):
            return
        
        t = this['_keyPriorReset'] = this['_key']
        r = t['words']

        e = int(t['sigBytes'] / 4)
        this['_nRounds'] = e + 6
        i = int(4 * (this['_nRounds'] + 1))
        n = this['_keySchedule'] = dict()
        n['length'] = this['_keySchedule']['length'] = 0
        o = 0

        myprint(this,t,r,e,i,o)
        
        while o < i:
            if o < e:
                n[o] = r[o]
                n['length'] += 1
                #myprint('i',o,n)
            else:
                s = n[o - 1]
                #myprint('0',o,s)
                if o % e:
                    if 6 < e:
                        if o % e == 4:
                            s = toSigned32(h[s >> 24] << 24)
                            s |= toSigned32(h[s >> 16 & 255] << 16)
                            s |= h[s >> 8 & 255] << 8
                            s |= h[255 & s]
                else:
                    if s < 0:
                        s = s + 2**32 # convert signed to unsigned
                    s0 = toSigned32(s << 8 | s >> 24)
                    s0 = int(bin(s0 & 0b11111111111111111111111111111111),2)
                        
                    #myprint('e1',o,'s=',s,'s0=',s0) #94307481
                    x = s0 >> 24
                    s = toSigned32(h[x] << 24)
                    #myprint('e11',o,x,s)

                    x = s0 >> 16 & 255
                    s |= toSigned32(h[x] << 16)
                    #myprint('e111',o,x,toSigned32(h[x] << 16),s)

                    x = s0 >> 8 & 255
                    s |= toSigned32(h[x] << 8)
                    #myprint('e1111',o,x,toSigned32(h[x] << 8),s)

                    x = 255 & s0
                    s |= h[x]
                    #myprint('e2',o,x,h[x],s)
                    
                    s ^= toSigned32(w[int(o / e) | 0] << 24)
                    #myprint('e3',o,s)
                n[o] = n[o - e] ^ s
                n['length'] += 1
                #myprint('f',o,n) 
                    
            o += 1

        this['_keySchedule'] = n
        myprint('this[_keySchedule]=',n)

        v = self._v
        y = self._y
        g = self._g
        _ = self.__
        
        a = this['_invKeySchedule'] = dict()
        a['length'] = this['_invKeySchedule']['length'] = 0
        c = 0

        while c < i:
            o = i - c
            if c % 4:
                s = n[o]
            else:
                s = n[o - 4] 

            if c < 4 or o <= 4:
                a[c] = s
            else:
                s0 = s
                s = int(bin(s & 0b11111111111111111111111111111111),2)
                #myprint('aa',s0,s,s0>>24,s>>24)
                aa = v[h[s >> 24]]
                #myprint('aa',s>>24,h[s>>24],v[h[s >> 24]])
                bb = _[h[s >> 16 & 255]]
                cc = y[h[s >> 8 & 255]]
                dd = g[h[255 & s]]
                a[c] = aa ^ bb ^ cc ^ dd
                #myprint(s,aa,bb,cc,dd,a[c])
            a['length'] += 1
            #myprint(c,o,s,a)
            c += 1

        # Copy a[] to _invKeySchedule[]
        this['_invKeySchedule'] = a
        myprint('this[_invKeySchedule]=',a)

    #VM:1166
    def _reset(self, xcryptor):
        self._doReset(xcryptor)
    
    #VM:1053
    def _createEncryptor(self, k, iv):
        t = MyAES.MyEncryptor(self, k, iv)
        return t

    def _createDecryptor(self, k, iv):
        t = MyAES.MyDecryptor(self, k, iv)
        return t

    #VM:1183 
    def _doFinalize(self, this): # this = _cipher
        t = this['cfg']['padding']
        if this['_xformMode'] == self.ENC_XFORM_MODE:
            t['pad'](this['_data'], this['blockSize'])
            r = self._process(this, True)
            myprint('r=',r)
        else:
            r = self._process(this, True)
            myprint('r=',r)
            t['unpad'](r)
        return r
            
    #VM:1073
    def _finalize(self, this, t): # this= xcryptor.this
        myprint('t=', t)
        myprint('type of t=',type(t))
        if 'str' in str(type(t)):	# Encrypt mode
            # Convert t from string to dict
            tt = utf8Parse(t)
            ttt = self._concat(this['_data'], tt)
        else:
            ttt = self._concat(this['_data'], t)
        this['_nDataBytes'] += ttt['sigBytes']
        myprint('ttt=',ttt, '_nDataBytes=', this['_nDataBytes'])
        return self._doFinalize(this)
        
    #VM:1232
    def _cryptoAESencrypt(self, plainText, keyUtf8, ivUtf8, op):
        #myprint(plainText)
        myprint('keyUtf8=',keyUtf8)
        myprint('ivUtf8=',ivUtf8)

        self._this = dict()
        self._this['__creator'] = dict()
        self._this['__creator']['name'] = "createEncryptor"
        self._this['__creator']['length'] = 2
        self._this['_iv'] = ivUtf8

        encryptor = self._createEncryptor(keyUtf8, ivUtf8)
        
        self._this['_cipher'] = encryptor.this
        myprint(self._this['_cipher'])
        o = self._finalize(self._this['_cipher'], plainText)
        s = self._this['_cipher']['cfg']

        ciphertext = o
        key        = keyUtf8
        iv         = ivUtf8
        algorithm  = self._this['_cipher']
        padding    = s['padding']
        blockSize  = self._this['_cipher']['blockSize']
        formatter = dict()
        formatter['parse'] = self._parse
        formatter['stringify'] = self._stringify

        ret = dict()
        ret['ciphertext'] = ciphertext
        ret['key']        = key
        ret['iv']         = iv
        ret['algorithm']  = algorithm
        ret['padding']    = padding
        ret['blockSize']  = blockSize
        ret['formatter']  = formatter
        return ret
        
    # Main entry points
    def encrypt(self, plainText):
        op = dict()
        op['iv'] = self._ivUtf8
        myprint(op)
        
        v = self._cryptoAESencrypt(plainText, self._keyUtf8, self._ivUtf8, op)
        return self._toString(v)

    def decrypt(self, encrypted):
        op = dict()
        op['iv'] = self._ivUtf8
        myprint(op)

        v = self._cryptoAESdecrypt(encrypted, self._keyUtf8, self._ivUtf8, op)
        w = self._toString(v)
        return w
    
    def _cryptoAESdecrypt(self, encrypted, keyUtf8, ivUtf8, op):
        myprint('keyUtf8=',keyUtf8)
        myprint('ivUtf8=',ivUtf8)

        self._this = dict()
        self._this['__creator'] = dict()
        self._this['__creator']['name'] = "createDecryptor"
        self._this['__creator']['length'] = 2
        self._this['_iv'] = ivUtf8
        
        decryptor = self._createDecryptor(keyUtf8, ivUtf8)
        self._this['_cipher'] = decryptor.this

        r = self._parse(self._this, encrypted, decryptor.this['formatter'])
        myprint('_cipher=',self._this['_cipher'])
        o = self._finalize(self._this['_cipher'], r['ciphertext'])
        myprint('o=',o)

        ciphertext = o
        key        = keyUtf8
        iv         = ivUtf8
        formatter  = self._this['_cipher']['formatter']
        blockSize  = self._this['_cipher']['blockSize']

        ret = dict()
        ret['ciphertext'] = ciphertext
        ret['key']        = key
        ret['iv']         = iv
        ret['blockSize']  = blockSize
        ret['formatter']  = formatter
        return ret
    
    def _AESclamp(self, this):
        t = this['words']
        r = this['sigBytes']

        try:
            oval = t[r >> 2]
            t[r >> 2] &= 4294967295 << 32 - r % 4 * 8
            if oval != t[r >> 2]:
                myprint('t[%d] has changed from %d to %d' % (r>>2,oval, t[r >> 2]))
            else:
                myprint('Unmodified t[%d]: %d' % (r>>2, t[r >> 2]))
            t['length'] = math.ceil(r / 4)
            myprint('t[length] =',t['length'])
        except:
            myprint('passing')
            pass

    def _pad(self, t, r):
        e = 4 * r
        i = e - t['sigBytes'] % e
        n = i << 24 | i << 16 | i << 8 | i
        o = dict()
        s = 0

        j = 0
        
        while s < i:
            o[j] = n
            s += 4
            j += 1
        o['length'] = len(o)

        myprint(e,i,n,o,s,r)
        
        c = dict()
        c['words'] = o
        if None != i:
            c['sigBytes'] = i
        else:
            c['sigBytes'] = 4 * o['length']
        myprint(e,i,n,o,s,r,c)
        self._concat(t, c)
        
    #VM: 1156
    def _unpad(self, t):
        r = 255 & t['words'][t['sigBytes'] - 1 >> 2]
        t['sigBytes'] -= r
        myprint('r=',r,'t=',t)
        
    def _process(self, this, t): # this=_cipher
        r = this['_data']
        e = r['words']
        i = r['sigBytes']
        n = this['blockSize']
        o = i / (4 * n)
        if o : #DP o == t
            s = math.ceil(o) * 4
            myprint('0 s=',s)
        else:
            s = max((0 | int(o)) - this['_minBufferSize'], 0) * n
            myprint('1 s=',s)
        a = min(4 * s, i)
        myprint('t=',t,'i=',i,'n=',n,'o=',o,'s=',s,'e=',e,'a=',a)
        if s:
            c = 0
            while c < s:
                this['processBlock'](e, c)
                c += n
            h = splice(e, 0, s)
            myprint('h=',h)
            r['sigBytes'] -= a
            myprint('r[sigBytes]=', r['sigBytes'])
        
        ret = dict()
        ret['words'] = h
        ret['sigBytes'] = a
        myprint('ret=',ret)
        return ret
            
    def doCryptBlock(self, this, t, r, e, i, n, o, s, a): # this = _cipher
        myprint(t)

        c = this['_nRounds']
        h = t[r] ^ e[0]
        f = t[r + 1] ^ e[1]
        l = t[r + 2] ^ e[2]
        u = t[r + 3] ^ e[3]
        d = 4
        p = 1

        myprint(c,h,f,l,u,d,p)
        
        while p < c:
            if h < 0:
                h = h + 2**32 # convert signed to unsigned
            v = i[h >> 24] ^ n[f >> 16 & 255] ^ o[l >> 8 & 255] ^ s[255 & u] ^ e[d]
            v = toSigned32(v)
            d += 1
            #myprint('v=',v)
            
            if f < 0:
                f = f + 2**32 # convert signed to unsigned
            _ = i[f >> 24] ^ n[l >> 16 & 255] ^ o[u >> 8 & 255] ^ s[255 & h] ^ e[d]
            _ = toSigned32(_)
            d += 1
            
            if l < 0:
                l = l + 2**32 # convert signed to unsigned
            y = i[l >> 24] ^ n[u >> 16 & 255] ^ o[h >> 8 & 255] ^ s[255 & f] ^ e[d]
            y = toSigned32(y)
            d += 1
            
            if u < 0:
                u = u + 2**32 # convert signed to unsigned
            g = i[u >> 24] ^ n[h >> 16 & 255] ^ o[f >> 8 & 255] ^ s[255 & l] ^ e[d]
            g = toSigned32(g)
            d += 1
            
            h = v
            f = _
            l = y
            u = g

            #myprint(p,h,f,l,u)
            p +=1

        #myprint(p,h,f,l,u)            
        if h < 0:
            h = h + 2**32 # convert signed to unsigned
        v = (a[h >> 24] << 24 | a[f >> 16 & 255] << 16 | a[l >> 8 & 255] << 8 | a[255 & u]) ^ e[d]
        d += 1
        v = toSigned32(v)

        if f < 0:
            f = f + 2**32 # convert signed to unsigned
        _ = (a[f >> 24] << 24 | a[l >> 16 & 255] << 16 | a[u >> 8 & 255] << 8 | a[255 & h]) ^ e[d]
        d += 1
        _ = toSigned32(_)        
        
        if l < 0:
            l = l + 2**32 # convert signed to unsigned
        y = (a[l >> 24] << 24 | a[u >> 16 & 255] << 16 | a[h >> 8 & 255] << 8 | a[255 & f]) ^ e[d]
        d += 1
        y = toSigned32(y)
        
        if u < 0:
            u = u + 2**32 # convert signed to unsigned
        g = (a[u >> 24] << 24 | a[h >> 16 & 255] << 16 | a[f >> 8 & 255] << 8 | a[255 & l]) ^ e[d]
        d += 1
        g = toSigned32(g)
        
        t[r] = v
        t[r + 1] = _
        t[r + 2] = y
        t[r + 3] = g
        myprint('t=',t)
            
    def _func_o(self, this, t, r, e): # this=_cipher, t=words, r=int
        myprint(this)
        i = this['pthis']['_iv']['words'] if this['pthis']['_iv'] else None
        myprint('i=',i)
        myprint('t=',t)
        myprint('r=',r)
        if i != None:
            n = i
            myprint('Setting this[parent][_iv] to None')
            this['pthis']['_iv'] = None
        else:
            n = this['_prevBlock']

        myprint('n=',n)
        o = 0
        while o < e:
            #myprint(t[r + o],n[o])
            t[r + o] ^= n[o]
            o += 1
            
        myprint('t=',t)

    def stringify(self, this):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD ')
        sys.exit(1)
        
    #VM: 49
    def _concat(self, this, t): #this=_data
        r = this['words']
        e = t['words']
        i = this['sigBytes']
        n = t['sigBytes']
        myprint('r=',r)
        myprint('e=',e)
        myprint('i=',i,'n=',n,'t=',t)

        self._AESclamp(this)

        if i % 4:
            o = 0
            while o < n:
                s = e[o >> 2] >> 24 - o % 4 * 8 & 255
                myprint(o,n,s,i+o>>2)
                # Extend r{} if needed
                try:
                    r[i + o >> 2] |= s << 24 - (i + o) % 4 * 8
                except:
                    r[i + o >> 2] = s << 24 - (i + o) % 4 * 8
                myprint('r[i + o >> 2]=',r[i + o >> 2])
                o += 1
        else:
            o = 0
            while o < n:
                r[i + o >> 2] = e[o >> 2]
                o += 4
        r['length'] = len(r) - 1
        this['sigBytes'] += n
        myprint('this=',this)
        return this

    def _parse(self, this, t, r):  # this = pthis, t = encryptedText, r = self._this['i']['format']
        myprint('t=',t)
        if 'str' in str(type(t)):
            return r['parse'](t, this)
        else:
            return t

    def _b64Stringify(self, this, t): # this = b64enc
        r = t['words']
        e = t['sigBytes']
        i = this['_map']
        myprint(r,e,i)
        self._AESclamp(t)

        n = list()
        o = 0
        while o < e:
            s  = (r[o >> 2] >> 24 - o % 4 * 8 & 255) << 16
            if (o + 1 >> 2) < r['length']:
                s |= (r[o + 1 >> 2] >> 24 - (o + 1) % 4 * 8 & 255) << 8
            if (o + 2 >> 2) < r['length']:
                s |= r[o + 2 >> 2] >> 24 - (o + 2) % 4 * 8 & 255
            a = 0
            while a < 4 and o + .75 * a < e:
                #myprint('2:',a,e,s,o,s >> 6 * (3 - a) & 63,n,o + .75 * a)
                n.append(i[s >> 6 * (3 - a) & 63])
                a += 1
            o += 3
            #myprint(len(n),n)
        c = i[64]
        if c:
            while len(n) % 4:
                n.append(c)
        return "".join(n)
            
    #VM:1205
    def _stringify(self, this):
        myprint('TBD TBD TBD TBD TBD TBD TBD TBD TBD TBD')
        r = this['ciphertext']
        try:
            e = this['salt']
        except:
            e = None

        myprint('No salt')

        if e:
            # i = c.create([1398893684, 1701076831]).concat(e).concat(r)
            myprint('TBD TBD TBD TBD TBD TBD TBD TBD ')
            sys.exit(1)
        else:
            i = r

        b64enc = dict()
        b64enc['stringify'] = self._b64Stringify
        b64enc['_map'] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        return self._b64Stringify(b64enc, i)
            
    #VM: 1200 / 45
    def _toString(self, this):
        formatter = this['formatter']
        ret = formatter['stringify'](this)
        myprint(ret)
        return ret

####        
def splice(d, s, e):
    myprint('d=',d,'s=',s,'e=',e)
    r = dict()
    i = 0
    while s < e:
        r[i] = d[s]
        del(d[s])
        i += 1
        s += 1
    r['length'] = len(r)
    myprint('r=',r)
    return r
    
def slice(d,s,e):
    myprint('d=',d,'s=',s,'e=',e)
    r = dict()
    i = 0
    while s < e:
        r[i]=d[s]
        i += 1
        s += 1
    r['length'] = len(r)
    myprint('r=',r)
    return r

def toSigned32(n):
    n = n & 0xffffffff
    return (n ^ 0x80000000) - 0x80000000

def utf8Parse(t):
    r = len(str(t))
    tAsString = str(t)
    myprint(tAsString,r)
    e = dict()
    i = 0
    while i < r:
        try:
            x = e[i >> 2]
        except:
            e[i >> 2] = 0
            
        e[i >> 2] |= (255 & ord(tAsString[i])) << 24 - i % 4 * 8
        i += 1
    e['length'] = len(e)

    d = dict()
    d['words'] = e
    d['sigBytes'] = r
    #myprint(d)
    return d

####
def module_path(local_function):
    ''' returns the module path without the use of __file__.  
    Requires a function defined locally in the module.
    from http://stackoverflow.com/questions/729583/getting-file-path-of-imported-module'''
    return os.path.abspath(inspect.getsourcefile(local_function))

def myprint(*args, **kwargs):
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
        END       = '\033[0m'

        #example: print(color.BOLD + 'Hello World !' + color.END)

    """My custom print() function."""
    # Adding new arguments to the print function signature 
    # is probably a bad idea.
    # Instead consider testing if custom argument keywords
    # are present in kwargs
    if config.DEBUG:
        __builtin__.print('%s%s()%s:' % (color.BLUE, inspect.stack()[1][3], color.END), *args, **kwargs)

####        
# Arguments parser
def parse_argv():
    desc = 'Argument parser for AES encryption/decryption'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-d", "--debug",
                        action="store_true", dest="debug", default=False,
                        help="print debug messages (to stdout)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt",
                       action="store_true",
                       dest="encryptMode",
                       default=False,
                       help="Test AES Encryption")
    group.add_argument("-x", "--decrypt",
                       action="store_true",
                       dest="decryptMode",
                       default=False,
                       help="Test AES Decryption")

    parser.add_argument('-f', '--file',
                        dest='logFile',
                        const=config.LOGFILE,
                        default=None,
                        action='store',
                        nargs='?',
                        metavar = 'FILE',
                        help="write debug messages to FILE")
    parser.add_argument("-i", "--info",
                        action="store_true", dest="version", default=False,
                        help="print version and exit")
    args = parser.parse_args()
    return args

def main():
    args = parse_argv()    

    if args.version:
        print('%s: version 1.0' % sys.argv[0])
        sys.exit(0)

    if args.debug:
        config.DEBUG = True

    if args.logFile == None:
        #print('Using stdout')
        pass
    else:
        if args.logFile == '':
            config.LOGFILE = "%s-%s-debug.txt" % (sys.argv[0], 'Encrypt' if args.encryptMode else 'Decrypt')
        else:
            config.LOGFILE = args.logFile
        print('Using log file: %s' % config.LOGFILE)
        try:
            sys.stdout = open(config.LOGFILE, "w")
        except:
            print('Cannot create log file')

    if not args.encryptMode and not args.decryptMode:
        print('You must set the requested mode (-e / -x)')
        sys.exit(1)

    IV = "1609088003850873"; KEY= "1609088003850494"
    key = KEY
    iv  = IV

    if args.encryptMode == True:
        print('TESTING ENCRYPTION')
        #msg = input('Message...: ')
        #key = input('Key...: ')
        #iv = input('Init Vector...: ')

        MSG2ENCRYPT = "1&1&1&8" + "\r\n" + "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,3" + "\r\n" + "modelName" + "\r\n" + "description" + "\r\n" + "X_TP_IsFD" + "\r\n" + "[ETH_SWITCH#0,0,0,0,0,0#0,0,0,0,0,0]1,1" + "\r\n" + "numberOfVirtualPorts" + "\r\n" + "[SYS_MODE#0,0,0,0,0,0#0,0,0,0,0,0]2,0" + "\r\n" + "[/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0" + "\r\n"
        
        print('Encrypting: %s' % MSG2ENCRYPT)
        print('Encrypted Text:', MyAESCipher(key).encrypt(iv, MSG2ENCRYPT))

    if args.decryptMode == True:
        print('\nTESTING DECRYPTION')

        MSG2DECRYPT = "xAQ1oviGtYOHfQz7WLDRp1DtE2gp6CwElmmZ5/+LkWdzJzhdfyQBcmDaG8Zyn5e77ixVK0HsaHdVTRl+dlQthHG9bljulvYMEfXGhQrjwoITmlGKpbKrHgVHH/vmHOG75YMktdkeaICJ0Z0f2sOcsMqWCymWTe6Qfua7MvSEd/SWmwk1RRX25ZldrAYZYCBASrtb5SSTMRICbihrnrfLn41MmgA96+bDA9/Zt6pg4vDq/ERVOzqWXjsnyjXj8pOu5oTqti0Y99ilRfqQDHk1UuN/TWtBEn1B9hOE86lgZhmZ7vZuZUNzWiPjd6IgKj95lX1GB2sGWJKJRdzEQCk+zrHoEA/Gg6MzmFG9B5jf561DpqP8soxtsW1CiBmKOvho3DpN/bws1exBHxgkYMJ4wTM9V0px+Ppu1GDKIMT2DKZpYAcfDy77s2QDZXQ32R9IcmTeUyN322aFekcyqI4VAd7bX1j7fh2o+VgiEcJkJOLmu0yrOCb0nwi3i46RZ/2NkCHlVkq8YqniV0IT3To7KBI6ZFCGCgPu1PwuO7xl/uWgJjBCSqaVh1F5haD4h4zpV2Wf2/aD/R4Pfx2SWS89b6Pwra1Kz59r/FVxcviS1SioPdRtpDD3bLGiRiF5/IcHaJ9lSihdlr0/koiu8JmRmh80z9vYCnpg7T4N3szJP6TqKooF2KWfAIXfRarAE3vHdJzvZEJMUZaqpz0hkdac55GQWfny+tyAmUPsYqIcrWkbX889Kzl6p14QtcWUFoY5mfmNP5dKWjqI2OUCWaV0mA=="
        
        print('Decrypting Text: %s' % MSG2DECRYPT)
        #cte = input('Ciphertext: ')
        #key = input('Key...: ')
        #iv = input('Init Vector...: ')
        print('Decrypted Text:', MyAESCipher(key).decrypt(iv, MSG2DECRYPT))

    if args.logFile and args.logFile != '':
        sys.stdout.close()

####
if __name__ == '__main__':
    main()
