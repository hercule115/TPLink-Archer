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

import requests
from bs4 import BeautifulSoup
import hashlib

try:
    import config	# Shared global config variables (DEBUG,...)
except:
    print('config.py does not exist. Importing generator')
    import initConfig	# Check / Update / Create config.py module
    
# My own AES crypto
import MyAESCrypto

# My own RSA crypto
import MyRSACrypto

class MyXcryptor():
    def __init__(self, nn, ee, seq):
        self.nn = nn
        self.ee = ee
        self._seq = int(seq)
        self._aesKeyString = ''
        self._hash = ''

        myprint('Creating AES and RSA instances')
        self.aes = MyAESCrypto.MyAES()
        self.rsa = MyRSACrypto.MyRSA(self.nn, self.ee)
        
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

    def setRSAKey(self, nn, ee):
        self.rsa.setKey(nn, ee)

    def setRSAStringKey(string):
        self.rsa.setStringKey(string)

    def getRSAKey():
        return self.rsa.getKeyString()

    def genAESKey(self):
        self.aes.genKey()
        self._aesKeyString = self.aes.getKeyString()
        myprint('self._aesKeyString=',self._aesKeyString)

    def getAESKey(self):
        return self.aes.getKeyString()
    
    def setAESStringKey(self, string):
        self._aesKeyString = string
        self.aes.setStringKey(string)

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
        self._configInfoCgiGdprRqst[12] = "1&5&5&5&1&5&5&1&5" + "\r\n" + "[L3_FORWARDING#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "__ifAliasName" + "\r\n" + "[WAN_IP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]1,3" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "ConnectionType" + "\r\n" + "[WAN_PPP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]2,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[WAN_COMMON_INTF_CFG#0,0,0,0,0,0#0,0,0,0,0,0]3,1" + "\r\n" + "WANAccessType" + "\r\n" + "[L3_IP6_FORWARDING#0,0,0,0,0,0#0,0,0,0,0,0]4,1" + "\r\n" + "__ifAliasName" + "\r\n" + "[WAN_PPTP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]5,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[WAN_L2TP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]6,2" + "\r\n" + "Enable" + "\r\n" + "Name" + "\r\n" + "[SYS_MODE#0,0,0,0,0,0#0,0,0,0,0,0]7,2" + "\r\n" + "Mode" + "\r\n" + "lteBackupEnable" + "\r\n" + "[WAN_LTE_LINK_CFG#0,0,0,0,0,0#0,0,0,0,0,0]8,0" + "\r\n"

        self._configInfoCgiGdprRqst[13] = "1&1" + "\r\n" + "[LTE_NET_STATUS#2,1,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

        self._configInfoCgiGdprRqst[14] = "1" + "\r\n" + "[WAN_IP_CONN#2,1,1,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"
        #...
        self._configInfoCgiGdprRqst[15] = "1&1&1" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[LTE_WAN_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,3" + "\r\n" + "dataSwitchStatus" + "\r\n" + "networkPreferredMode" + "\r\n" + "roamingEnabled" + "\r\n" + "[WAN_LTE_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]2,1" + "\r\n" + "dataLimit" + "\r\n"

        self._configInfoCgiGdprRqst[16] = "1&1&1&1&1" + "\r\n" + "[WAN_COMMON_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n" + "[WAN_LTE_INTF_CFG#2,0,0,0,0,0#0,0,0,0,0,0]1,8" + "\r\n" + "dataLimit" + "\r\n" + "enablePaymentDay" + "\r\n" + "curStatistics" + "\r\n" + "totalStatistics" + "\r\n" + "enableDataLimit" + "\r\n" + "limitation" + "\r\n" + "curRxSpeed" + "\r\n" + "curTxSpeed" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]2,0" + "\r\n" + "[LTE_PROF_STAT#2,1,0,0,0,0#0,0,0,0,0,0]3,0" + "\r\n" + "[LTE_NET_STATUS#2,1,0,0,0,0#0,0,0,0,0,0]4,0" + "\r\n"

        self._configInfoCgiGdprRqst[17] = "1" + "\r\n" + "[WAN_IP_CONN#2,1,1,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"

        self._configInfoCgiGdprRqst[18] = "1&1" + "\r\n" + "[DIAG_TOOL#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "LastResult" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

        self._configInfoCgiGdprRqst[19] = "7" + "\r\n" + "[ACT_DIAG_STARTDIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,0" + "\r\n"

        self._configInfoCgiGdprRqst[20] = "1&1" + "\r\n" + "[DIAG_TOOL#0,0,0,0,0,0#0,0,0,0,0,0]0,1" + "\r\n" + "LastResult" + "\r\n" + "[WAN_LTE_LINK_CFG#2,1,0,0,0,0#0,0,0,0,0,0]1,0" + "\r\n"

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
        #myprint('session cookies:',self._session.cookies)
        #dumpToFile('%s-%d.html' % (self._hostName,doParse), r.text)
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
                        const='',
                        default=None,
                        action='store',
                        nargs='?',
                        metavar = 'FILE',
                        help="write debug messages to FILE (default to <hostname>-debug.txt)")
    parser.add_argument('-r', '--router',
                        dest='hostName',
                        action='store',
                        #nargs='?',
                        help="TP-Link Archer router IP address/name (default to %s)" % config.ROUTER_HOSTNAME)
    parser.add_argument('-u', '--user',
                        dest='userName',
                        help="Username to use for login (default to %s)" % (config.ROUTER_USERNAME))
    parser.add_argument('-p', '--password',
                        dest='password',
                        help="Password to use for login")
    parser.add_argument("-i", "--info",
                        action="store_true", dest="version", default=False,
                        help="print version and exit")
    args = parser.parse_args()
    return args

####
def import_module_by_path(path):
    name = os.path.splitext(os.path.basename(path))[0]
    if sys.version_info[0] == 2:
        import imp
        return imp.load_source(name, path)
    elif sys.version_info[:2] <= (3, 4):
        from importlib.machinery import SourceFileLoader
        return SourceFileLoader(name, path).load_module()
    else:
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

#
# Import Archer module. Must be called *after* parsing arguments
#
def importModule(moduleDirPath, moduleName, name):
    modulePath = os.path.join(moduleDirPath, moduleName)
    mod = import_module_by_path(modulePath)
    globals()[name] = mod

####
def main():
    args = parse_argv()

    if args.version:
        print('%s: version 1.1' % sys.argv[0])
        sys.exit(0)

    if args.debug:
        config.DEBUG = True

    #if args.logFile:
    #    config.LOGFILE = args.logFile
        
    with requests.session() as session:
        if args.hostName:
            config.ROUTER_HOSTNAME = args.hostName
            
        if args.userName:
            config.ROUTER_USERNAME = args.userName
            
        if not config.ROUTER_USERNAME:
            userName = input('Username <Default=admin>:' )
            if not userName:
                config.ROUTER_USERNAME = 'admin'

        if args.password:
            config.ROUTER_PASSWORD = args.password
        if not config.ROUTER_PASSWORD:
            password = getpass.getpass()
            if not password:
                myprint('Invalid empty password')
                sys.exit(1)
            config.ROUTER_PASSWORD = password

        if args.logFile == None:
            #print('Using stdout')
            pass
        else:
            if args.logFile == '':
                config.LOGFILE = "%s-debug.txt" % config.ROUTER_HOSTNAME
            else:
                config.LOGFILE = args.logFile
            print('Using log file: %s' % config.LOGFILE)
            try:
                sys.stdout = open(config.LOGFILE, "w")
            except:
                print('Cannot create log file')

        # Create instance of router at hostName, connect with given credentials
        archer = Archer(config.ROUTER_HOSTNAME, config.ROUTER_USERNAME, config.ROUTER_PASSWORD, session)

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
        print('Hostname: %s, Model: %s, BSSID: %s, IPv4: %s' %(config.ROUTER_HOSTNAME, modelName, bssid, ipv4))
        #print('BSSID: %s' % archerConfig['BSSID'])
        print('Usage: %s / %s' % (humanBytes(totalStatistics), humanBytes(limitation)))

        if args.logFile and args.logFile != '':
            sys.stdout.close()
        
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

    # config parameters updated. Import MyAESCrypto module
    importModule(moduleDirPath, 'MyAESCrypto.py', 'MyAESCrypto')

    #modulenames = set(sys.modules) & set(globals())
    #allmodules = [sys.modules[name] for name in modulenames]
    #print(allmodules)

    main()
