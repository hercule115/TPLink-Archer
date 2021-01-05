#!/usr/bin/env python

import builtins as __builtin__
import inspect
import os
import socket
import sys
import time
import requests
import argparse
import getpass

def checkModule(fields):
    for f in fields:
        ftype = f[0]
        fname = f[1]

        try:
            a = getattr(config, "%s" % fname)
            if a == '':
                print('Invalid config.py file (attribute %s is nil)' % fname)
                return -1
            continue
        except:
            print('Invalid config.py file (Missing attribute %s)' % fname)
            return -1
    return 0
        
def _createDict(fields, opt=True):
    d = dict()
    for f in fields:
        ftype = f[0]
        fname = f[1]

        if ftype == 'b':
            v = input('%s (True/False): ' % fname)
            if opt:
                if v != '':
                    while v!='False' and v!='True':
                        v = input('%s (True/False): ' % fname)
            else: # Mandatory. Can't be null
                while not v or (v!='False' and v!='True'):
                    v = input('%s (True/False): ' % fname)
            d[fname]=v

        elif ftype == 'p':
            v = getpass.getpass(prompt='%s: ' % fname)
            if not opt:
                while not v:
                    v = getpass.getpass(prompt='%s (string): ' % fname)
            d[fname]="'%s'" % v
                
        elif ftype == 's':
            v = input('%s (string): ' % fname)
            if not opt:
                while not v:
                    v = input('%s: ' % fname)
            d[fname]="'%s'" % v
            
        elif ftype == 'd':
            v = input('%s (decimal): ' % fname)
            if not opt:
                while not v:
                    v = input('%s: ' % fname)
            d[fname]=v
                
    return d

def createConfig(mandatoryFields, optionalFields):
    print('** Setting mandatory attributes **')
    m = _createDict(fields=mandatoryFields, opt=False)
    print('** Setting optional attributes **')
    o = _createDict(fields=optionalFields, opt=True)

    #print(m)
    #print(o)
    
    # Create config.py with collected information
    try:
        with open('config.py', 'w') as configFile:
            configFile.write('# Mandatory parameters\n')
            for k,v in m.items():
                configFile.write("%s = %s\n" % (k,v))

            configFile.write('\n')
            
            configFile.write('# Optional parameters (may be null)\n')
            for k,v in o.items():
                configFile.write("%s = %s\n" % (k,v))
                
    except IOError as e:
        msg = "I/O error: Creating %s: %s" % ('config.py', "({0}): {1}".format(e.errno, e.strerror))
        print(msg)
        sys.exit(1)

def initConfig(moduleDirPath, mandatoryFields, optionalFields):
    #configModulePath = os.path.join(moduleDirPath, 'config.py')
    try:
        import config
        globals()['config'] = config
    except:
        print('Creating config.py')
        createConfig(mandatoryFields, optionalFields)
    else:
        #print('Checking existing config.py')
        ret = checkModule(fields=mandatoryFields)
        if ret < 0:
            createConfig(mandatoryFields, optionalFields)

# Entry point    
if __name__ == "__main__":
    mandatoryFields = [('b','DEBUG'), ('s','NOIP_USERNAME'), ('p','NOIP_PASSWORD'), ('s','NOIP_HOSTNAME'), ('d','TIMEOUT')]
    optionalFields  = [('s','ROUTER_USERNAME'), ('p','ROUTER_PASSWORD'), ('s','ROUTER_HOSTNAME')]

    initConfig('.', mandatoryFields, optionalFields)
