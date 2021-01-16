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
import shutil
import glob

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
    print('Router User Password: %s' % masked(config.ROUTER_PASSWORD, 3))

# Leave the last 'l' characters of 'text' unmasked
def masked(text, l):
    nl=-(l)
    masked = text[nl:].rjust(len(text), "#")
    return masked

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
def cleanLog(logDir):
    dirs = list(filter(os.path.isdir, glob.glob(logDir + "16*")))
    dirs.sort(key=lambda x: os.path.getmtime(x))
    print('Logs to clean:',dirs[:-1])	# Skip last/current log directory
    for d in dirs[:-1]:
        shutil.rmtree(d, ignore_errors=True)
        print('Deleting:',d)

def module_path(local_function):
    ''' returns the module path without the use of __file__.  
    Requires a function defined locally in the module.
    from http://stackoverflow.com/questions/729583/getting-file-path-of-imported-module'''
    return os.path.abspath(inspect.getsourcefile(local_function))

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

def myprint(*args, **kwargs):
    """My custom print() function."""
    # Adding new arguments to the print function signature 
    # is probably a bad idea.
    # Instead consider testing if custom argument keywords
    # are present in kwargs

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
    parser.add_argument("-c", "--clean",
                        action="store_true",
                        dest="cleanLogs",
                        default=False,
                        help="Clean old Logfiles and exit")
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
    ME = os.path.basename(sys.argv[0])
    print('%s: Running at: %s' % (ME, time.strftime('%m/%d/%y %H:%M:%S', time.localtime())))
    # Parse arguments 
    args = parse_argv()

    if args.version:
        print('%s: version 1.1' % ME)
        sys.exit(0)

    setConfigParams(args)

    # Clean old logfiles
    cleanLog('/volume1/Logs/synoscheduler/4/')
    if args.cleanLogs:
        sys.exit(0)
    
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
            dnsRecord = dnsRecord.rstrip(',')
        dnsIpAddr = dnsRecord
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
        msg = "{}: {} IP address of {} is: {}".format(curTime, 'DNS' if DNS_RESOLVER else 'Host', config.NOIP_HOSTNAME, dnsIpAddr)
        print(msg)
        print("{}: Public IP address (ISP) of {} is: {}".format(curTime, config.NOIP_HOSTNAME, routerIpAddr))
        if routerIpAddr in dnsIpAddr:
            print('%s: %sNo update is required.%s' % (curTime,color.RED,color.END))
        else:
            print('%s: %sSkipping update.%s' % (curTime, color.RED, color.END))
        sys.exit(0)

    # If uptodate, exit
    if routerIpAddr in dnsIpAddr:
        curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
        print('%s: %sNo update is required. Exiting%s' % (curTime,color.RED,color.END))
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
        print('%sFailed to update DDNS Record at No-Ip (%d)%s' % (color.RED,r,color.END))
        sys.exit(1)

    # Confirmation...
    dnsIpAddr = getHostByName(config.NOIP_HOSTNAME)
    time.sleep(5)
    curTime = time.strftime('%m/%d/%y %H:%M:%S', time.localtime())
    msg = "{}: {} IP address of {} is: {}".format(curTime, 'DNS' if DNS_RESOLVER else 'Host', config.NOIP_HOSTNAME, dnsIpAddr)
    print(msg)

    if config.NOIP_OTHER_HOSTS:
        otherHosts = config.NOIP_OTHER_HOSTS.split(';')
        for host in otherHosts:
            print('Updating host %s with IP %s' % (host,routerIpAddr))
            noip_args = Namespace(config   = '%s' % (os.path.expanduser("~")),
                                  provider = 'noip',
                                  hostname = '%s' % host,
                                  ip       = '%s' % routerIpAddr,
                                  usertoken= '%s' % config.NOIP_USERNAME,
                                  password = '%s' % config.NOIP_PASSWORD,
                                  store    = False,
                                  url      = None)
            r = updateDDNSRecord(noip_args)
            if r:
                print('%sFailed to update DDNS Record at No-Ip (%d)%s' % (color.RED,r,color.END))
                sys.exit(1)
            
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
                       ('s','NOIP_OTHER_HOSTS'),
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
