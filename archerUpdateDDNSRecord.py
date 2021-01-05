#!/usr/bin/env python

# Tool to update the DDNS record for the TP-LINK ARCHER MR600 router
# It uses my web Scrapping package to get the IP Address (public) of the router
# and the noipy package to update the DDNS record at No-IP

import builtins as __builtin__
import inspect
import os
import socket
import sys
import time
import requests
import argparse
import getpass

import initConfig # config.py generator

try:
    import dns.resolver
    DNS_RESOLVER = True
except:
    DNS_RESOLVER = False

class Namespace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# Set config parameters according to cmdline arguments
def setConfigParams(args):
    if args.debug:
        config.DEBUG = True

    if args.fqhn:
        config.NOIP_HOSTNAME = args.fqhn
    
    if args.hostName:
        config.HOSTNAME = args.hostName
            
    if args.userName:
        config.ROUTER_USERNAME = args.userName

    if args.password:
        config.ROUTER_PASSWORD = args.password
            
    #        if not config.PASSWORD:
    #            password = getpass.getpass()
    #            if not password:
    #                myprint('Invalid empty password')
    #                sys.exit(1)
    #            config.PASSWORD = password

    if args.logFile != None:
        if args.logFile == '':
            config.LOGFILE = "%s-debug.txt" % config.ROUTER_HOSTNAME
        else:
            config.LOGFILE = args.logFile
        print('Using log file: %s' % config.LOGFILE)
        try:
            sys.stdout = open(config.LOGFILE, "w")
        except:
            print('Cannot create log file')

    print('TP-Link Archer Router Connection Parameters:')
    print('Router Hostname/Address: %s' % config.ROUTER_HOSTNAME)
    print('Router User Name: %s' % config.ROUTER_USERNAME)
    print('Router User Password: %s' % config.ROUTER_PASSWORD)

def rebootRouter(args):
    with requests.session() as session:
        # Create instance of router at hostName, connect with given credentials
        archer = tplas.Archer(config.ROUTER_HOSTNAME, config.ROUTER_USERNAME, config.ROUTER_PASSWORD, session)

        # Reboot the router
        archer.reboot()
    
#
# Get some router information
#
def dumpInformationFromRouter(args):
    with requests.session() as session:
        # Create instance of router at hostName, connect with given credentials
        archer = tplas.Archer(config.ROUTER_HOSTNAME, config.ROUTER_USERNAME, config.ROUTER_PASSWORD, session)

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
        bssid      = archerConfig['BSSID'].split('; ')[0]

        print('Router Host: %s, Model: %s, BSSID: %s, Public IPv4: %s' % (config.ROUTER_HOSTNAME, modelName, bssid, ipv4))
        #print('BSSID: %s' % archerConfig['BSSID'])

        # Get usage statistics
        totalStatistics = int(float(archerConfig['totalStatistics']))
        limitation      = int(archerConfig['limitation'])
        print('Usage: %s / %s' % (humanBytes(totalStatistics), humanBytes(limitation)))

        if args.logFile and args.logFile != '':
            sys.stdout.close()

#
# Get the public IP address assigned by ISP to the TPLink
# Archer router using Web Scrapping
#
def getIpAddressFromRouter(args):
    with requests.session() as session:
        # Create instance of router at hostName, connect with given credentials
        archer = tplas.Archer(config.ROUTER_HOSTNAME, config.ROUTER_USERNAME, config.ROUTER_PASSWORD, session)

        # Read current configuration
        archerConfig = archer.getConfig()

        # Work done. Logout from router
        archer.logout()

        ipv4 = archerConfig['ipv4']

        if args.logFile and args.logFile != '':
            sys.stdout.close()
        return ipv4

#
# Update the DDNS Record at No-Ip with current IP address
#
def updateDDNSRecord(args):
    exe = sys.executable
    cmd = "%s -m noipy.main --usertoken %s --password %s --provider %s --hostname %s %s" % \
        (exe,
         args.usertoken,
         args.password,
         args.provider,
         args.hostname,
         args.ip)

    #print(cmd)
    r = os.system(cmd) 
    return r

def humanBytes(size):
    power = float(2**10)     # 2**10 = 1024
    n = 0
    power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size = float(size / power)
        n += 1
    return '%s %s' % (('%.2f' % size).rstrip('0').rstrip('.'), power_labels[n])

#
# Get router IP address from DNS
#
def resolveDNS(hostName):
    resolver = dns.resolver.Resolver(); 
    answer = resolver.query(hostName , "A")
    return answer

def getHostByName(hostName):
    try:
        ipAddress = socket.gethostbyname(hostName)
    except:
        ipAddress = '0.0.0.0'
        print("Unknown host: %s" % hostName)
    return ipAddress

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
        END       = '\033[0m'

    if config.DEBUG:
        __builtin__.print('%s%s()%s:' % (color.BOLD, inspect.stack()[1][3], color.END), *args, **kwargs)
    #__builtin__.print('%s():' % inspect.stack()[1][3], *args, **kwargs)

####    
# Arguments parser
def parse_argv():
    desc = 'Get TP-Link Archer router current configuration, as shown on the first page after login'

    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        default=False,
                        help="print debug messages (to stdout)")
    parser.add_argument('-f', '--file',
                        dest='logFile',
                        const='', #config.LOGFILE,
                        default=None,
                        action='store',
                        nargs='?',
                        metavar = 'FILE',
                        help="write debug messages to FILE (default to <hostname>-debug.txt)")
    parser.add_argument('--fqhn',
                        dest='fqhn',
                        action='store',
                        #nargs='?',
                        help="TP-Link Archer router Fully Qualified HostName (default to %s)" % config.NOIP_HOSTNAME)
    parser.add_argument('-r', '--router',
                        dest='hostName',
                        action='store',
                        #nargs='?',
                        help="TP-Link Archer router IP address/name (default to %s)" % config.ROUTER_HOSTNAME)
    parser.add_argument('-u', '--user',
                        dest='userName',
                        required=False,
                        help="Username for login on Archer router (default = admin)")
    parser.add_argument('-p', '--password',
                        dest='password',
                        required=True,
                        help="Password for login on Archer router")
    # Possible Actions
    parser.add_argument("-i", "--information",
                        action="store_true",
                        dest="dumpInformation",
                        default=False,
                        help="Dump router information and exit")
    parser.add_argument("-n", "--checkonly",
                        action="store_true",
                        dest="checkonly",
                        default=False,
                        help="Check if IP add needs update but don't do it")
    parser.add_argument("-R", "--reboot",
                        action="store_true",
                        dest="reboot",
                        default=False,
                        help="Reboot the Archer router and exit")
    parser.add_argument("-v", "--version",
                        action="store_true",
                        dest="version",
                        default=False,
                        help="Print version and exit")

    args = parser.parse_args()
    return args

####
#
# Import Archer module. Must be called *after* parsing arguments
#
def importArcher(moduleDirPath):
    archerModulePath = os.path.join(moduleDirPath, 'archer.py')
    tplas = importModuleByPath(archerModulePath)
    globals()['tplas'] = tplas

#
# If config.py does not exist or is incomplete, initialize it
#
def o_initConfig(moduleDirPath):
    configModulePath = os.path.join(moduleDirPath, 'config.py')
    try:
        #config = importModuleByPath(configModulePath)
        import config
        globals()['config'] = config
    except:
        print('Initializing config.py')
    else:
        if config.NOIP_USERNAME != '' and config.NOIP_PASSWORD != '' and config.NOIP_HOSTNAME != '':
            #print('Skipping config initialization')
            return

    h = input('NOIP Hostname: ')
    u = input('NOIP Username: ')
    p = getpass.getpass(prompt='NOIP Password: ')

    print('Initializing NOIP parameters in config.py')
    
    defaultConfigLines = ["DEBUG = False\n",
                          "LOCALTEST = False\n",
                          "LOGFILE = ''\n",
                          "\n",
                          "# Archer Router connection parameters\n",
                          "ROUTER_HOSTNAME = '192.168.1.1'\n",
                          "ROUTER_USERNAME = 'admin'\n",
                          "ROUTER_PASSWORD = ''\n",
                          "\n",
                          "# NO-IP connection parameters\n",
                          "NOIP_USERNAME = " + "'" + u + "'\n",
                          "NOIP_PASSWORD = " + "'" + p + "'\n",
                          "NOIP_HOSTNAME = " + "'" + h + "'\n"
    ]

    # Create config.py with collected information
    try:
        with open('config.py', 'w') as configFile:
            configFile.writelines(defaultConfigLines)
    except IOError as e:
        msg = "I/O error: Creating %s: %s" % ('config.py', "({0}): {1}".format(e.errno, e.strerror))
        print(msg)
        sys.exit(1)

    # Import generated module
    try:
        #config = import_module_by_path(configModulePath)
        import config
        globals()['config'] = config
    except:
        print('config.py initialization has failed. Exiting')
        sys.exit(1)

def importModuleByPath(path):
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
# Import given module.
#
def importModule(moduleDirPath, moduleName, name):
    modulePath = os.path.join(moduleDirPath, moduleName)
    mod = importModuleByPath(modulePath)
    globals()[name] = mod
    
####
def main():
    print('%s: Running at: %s' % (sys.argv[0], time.strftime('%m/%d/%y %H:%M:%S', time.localtime())))
    
    # Absolute pathname of directory containing this module
    #moduleDirPath = os.path.dirname(module_path(getIpAddressFromRouter))
    
    # Initialize/Import config.py
    #initConfig(moduleDirPath)

    # Parse arguments 
    args = parse_argv()

    if args.version:
        print('%s: version 1.1' % sys.argv[0])
        sys.exit(0)

    setConfigParams(args)
        
    # config parameters are updated. Import Archer module
    #importArcher(moduleDirPath)

    if args.dumpInformation:
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print('%s: Router Configuration (IP: %s)' % (curTime, config.ROUTER_HOSTNAME))
        dumpInformationFromRouter(args)
        sys.exit(0)
    
    if args.reboot:
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print('%s: Rebooting router (IP: %s)...' % (curTime, config.ROUTER_HOSTNAME))
        rebootRouter(args)
        sys.exit(0)

    # No action specified. Check router public address and update it if out of date
    
    # Get current IP address of router from DNS
    if DNS_RESOLVER:
        try:
            rec = resolveDNS(config.NOIP_HOSTNAME)
        except:
            print('No DNS Record for %s' % config.NOIP_HOSTNAME)
            dnsRecord = ''
        else:
            for item in rec:
                dnsRecord = ','.join([str(item), ''])

        dnsIpAddr = dnsRecord.rstrip(',')
        #print('Current DDNS Record for %s: %s' % (config.NOIP_HOSTNAME, dnsIpAddr))
    else:
        dnsIpAddr = getHostByName(config.NOIP_HOSTNAME)
    
    # Read IP address as assigned by ISP from router web interface
    routerIpAddr = getIpAddressFromRouter(args)
    if routerIpAddr == '':
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print('%s: Unable to retrieve IPv4 address for router (IP: %s)' % (curTime, config.ROUTER_HOSTNAME))
        print('You must reboot router')
        sys.exit(1)

    if args.checkonly:
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print("{}: DNS IP address of {} is: {}".format(curTime, config.NOIP_HOSTNAME, dnsIpAddr))
        print("{}: Public IP address (ISP) of {} is: {}".format(curTime, config.NOIP_HOSTNAME, routerIpAddr))
        if routerIpAddr in dnsIpAddr:
            print('%s: No update is required.' % curTime)
        else:
            print('%s: Skipping update.' % curTime)
        sys.exit(0)

    # If uptodate, exit
    if routerIpAddr in dnsIpAddr:
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print('%s: No update is required. Exiting' % curTime)
        sys.exit(0)

    # Create a namespace to pass arguments
    noip_args = Namespace(config   = '%s' % (os.path.expanduser("~")),
                          provider = 'noip',
                          hostname = '%s' % config.NOIP_HOSTNAME,
                          ip       = '%s' % routerIpAddr,
                          usertoken= '%s' % config.NOIP_USERNAME,
                          password = '%s' % config.NOIP_PASSWORD,
                          store    = False,
                          url      = None)
    r = updateDDNSRecord(noip_args)
    if r:
        myprint('Failed to update DDNS Record at No-Ip (%d)' % r)
        sys.exit(1)

    # Confirmation...
    dnsIpAddr = getHostByName(config.NOIP_HOSTNAME)
        
# Entry point    
if __name__ == "__main__":

    # Absolute pathname of directory containing this module
    moduleDirPath = os.path.dirname(module_path(main))

    # Create config.py with Mandatory/Optional fields 
    mandatoryFields = [('b','DEBUG'),
                       ('s','NOIP_HOSTNAME'),
                       ('s','NOIP_USERNAME'),
                       ('s','NOIP_PASSWORD')]
    
    optionalFields  = [('s','ROUTER_HOSTNAME'),
                       ('s','ROUTER_USERNAME'),
                       ('p','ROUTER_PASSWORD'),
                       ('s','LOGFILE')]

    initConfig.initConfig(moduleDirPath, mandatoryFields, optionalFields)

    # Import generated module
    try:
        import config
    except:
        print('config.py initialization has failed. Exiting')
        sys.exit(1)

    # config parameters updated. Import Archer module
    importModule(moduleDirPath, 'archer.py', 'tplas')

    main()
