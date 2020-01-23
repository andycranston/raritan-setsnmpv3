#! /usr/bin/python3
#
# @(!--#) @(#) setsnmpv3.py, version 010, 22-january-2020
#
# set up SNMP v3 on a Raritan intelligent PDU
#

#
# imports
#

import sys
import os
import argparse

import raritan.rpc.devsettings
import raritan.rpc.usermgmt
import raritan.rpc.um

########################################################################

#
# constants
#

DEFAULT_CONFIG_FILENAME = 'snmpv3.conf'
DEFAULT_HOST_FILENAME   = 'snmpv3.hosts'

########################################################################

def defaultparams():
    params = {}

    params['user']          = 'admin'
    params['userpass']      = 'raritan'
    params['snmpv3user']    = 'admin'
    params['securitylevel'] = 'none'
    params['authprotocol']  = 'SHA1'
    params['authpassword']  = ''
    params['privprotocol']  = 'DES'
    params['privpassword']  = ''

    return params

########################################################################

def readconfigfile(configfile, configfilename):
    global progname

    params = defaultparams()

    linenum = 0

    errorcount = 0

    for line in configfile:
        linenum += 1

        line = line.rstrip()

        if line == '':
            continue

        if line[0] == '#':
            continue

        equalpos = line.find('=')

        if equalpos == -1:
            print('{}: line {} in config file "{}" does not contain an equals sign'.format(progname, linenum, configfilename), file=sys.stderr)
            errorcount += 1
            continue

        if equalpos == 0:
            print('{}: line {} in config file "{}" starts with an equals sign'.format(progname, linenum, configfilename), file=sys.stderr)
            errorcount += 1
            continue

        if equalpos == (len(line) - 1):
            print('{}: line {} in config file "{}" ends with an equals sign'.format(progname, linenum, configfilename), file=sys.stderr)
            errorcount += 1
            continue

        if len(line) < 3:
            print('{}: line {} in config file "{}" is too short'.format(progname, linenum, configfilename), file=sys.stderr)
            errorcount += 1
            continue

        paramname = line[:equalpos].rstrip()

        paramvalue = line[equalpos+1:].strip()

        params[paramname] = paramvalue

        ### print('>>{}<<  >>{}<<'.format(paramname, paramvalue))

    configfile.close()

    return errorcount, params

########################################################################

def validparams(params):
    global progname

    errorcount = 0

    param = [ 'user', 'userpass', 'snmpv3user' ]

    for p in param:
        if params[p] == '':
            print('{}: parameter "{}" must not be the null (empty) string'.format(progname, p), file=sys.stderr)
            errorcount += 1

    sl = params['securitylevel']

    if ( (sl != 'disable') and (sl != 'none') and (sl != 'auth') and (sl != 'auth+priv') ):
        print('{}: parameter "{}" has an invalid value of "{}"'.format(progname, 'securitylevel;', sl), file=sys.stderr)
        errorcount += 1

    return errorcount

########################################################################

def setsnmpservice(host, params):
    print('Configuring SNMPv3 service on host "{}"'.format(host))

    agent = raritan.rpc.Agent("https", host, params['user'], params['userpass'], timeout=30, disable_certificate_verification=True)

    snmpproxy = raritan.rpc.devsettings.Snmp('/snmp', agent)

    snmpconf = snmpproxy.getConfiguration()

    updaterequired = False

    if snmpconf.v2enable != False:
        snmpconf.v2enable = False
        updaterequired = True

    if snmpconf.v3enable != True:
        snmpconf.v3enable = True
        updaterequired = True

    if updaterequired:
        snmpproxy.setConfiguration(snmpconf)

    return
    
########################################################################

def setsnmpuser(host, params):
    functiondebug = False

    print('Configuring SNMPv3 user "{}" on host "{}"'.format(params['snmpv3user'], host))

    agent = raritan.rpc.Agent("https", host, params['user'], params['userpass'], timeout=30, disable_certificate_verification=True)

    snmpv3userproxy = raritan.rpc.usermgmt.User('/auth/user/{}'.format(params['snmpv3user']), agent)

    snmpv3userinfo = snmpv3userproxy.getInfo()

    if functiondebug:
        print('Current SNMP v3 settings are:')
        print(snmpv3userinfo.snmpV3Settings)

    sl = params['securitylevel']

    if sl == 'disable':
        snmpv3userinfo.snmpV3Settings.enabled                           = False
        snmpv3userinfo.snmpV3Settings.secLevel                          = raritan.rpc.um.SnmpV3.SecurityLevel.NO_AUTH_NO_PRIV
        snmpv3userinfo.snmpV3Settings.authProtocol                      = raritan.rpc.um.SnmpV3.AuthProtocol.SHA1
        snmpv3userinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = True
        snmpv3userinfo.snmpV3Settings.haveAuthPassphrase                = False
        snmpv3userinfo.snmpV3Settings.authPassphrase                    = ''
        snmpv3userinfo.snmpV3Settings.privProtocol                      = raritan.rpc.um.SnmpV3.PrivProtocol.DES
        snmpv3userinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpv3userinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpv3userinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'none':
        snmpv3userinfo.snmpV3Settings.enabled                           = True
        snmpv3userinfo.snmpV3Settings.secLevel                          = raritan.rpc.um.SnmpV3.SecurityLevel.NO_AUTH_NO_PRIV
        snmpv3userinfo.snmpV3Settings.authProtocol                      = raritan.rpc.um.SnmpV3.AuthProtocol.SHA1
        snmpv3userinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = True
        snmpv3userinfo.snmpV3Settings.haveAuthPassphrase                = False
        snmpv3userinfo.snmpV3Settings.authPassphrase                    = ''
        snmpv3userinfo.snmpV3Settings.privProtocol                      = raritan.rpc.um.SnmpV3.PrivProtocol.DES
        snmpv3userinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpv3userinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpv3userinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'auth':
        ap = params['authprotocol']

        if ap.lower() == 'sha-1':
            authproto = raritan.rpc.um.SnmpV3.AuthProtocol.SHA1
        elif ap.lower() == 'md5':
            authproto = raritan.rpc.um.SnmpV3.AuthProtocol.MD5

        snmpv3userinfo.snmpV3Settings.enabled                           = True
        snmpv3userinfo.snmpV3Settings.secLevel                          = raritan.rpc.um.SnmpV3.SecurityLevel.AUTH_NO_PRIV
        snmpv3userinfo.snmpV3Settings.authProtocol                      = authproto
        snmpv3userinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = False
        snmpv3userinfo.snmpV3Settings.haveAuthPassphrase                = True
        snmpv3userinfo.snmpV3Settings.authPassphrase                    = params['authpassword'] 
        snmpv3userinfo.snmpV3Settings.privProtocol                      = raritan.rpc.um.SnmpV3.PrivProtocol.DES
        snmpv3userinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpv3userinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpv3userinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'auth+priv':
        ap = params['authprotocol']

        if ap.lower() == 'sha-1':
            authproto = raritan.rpc.um.SnmpV3.AuthProtocol.SHA1
        elif ap.lower() == 'md5':
            authproto = raritan.rpc.um.SnmpV3.AuthProtocol.MD5

        pp = params['privprotocol']

        if pp.lower() == 'des':
            privproto = raritan.rpc.um.SnmpV3.PrivProtocol.DES
        elif pp.lower() == 'aes-128':
            privproto = raritan.rpc.um.SnmpV3.PrivProtocol.AES128
       
        snmpv3userinfo.snmpV3Settings.enabled                           = True
        snmpv3userinfo.snmpV3Settings.secLevel                          = raritan.rpc.um.SnmpV3.SecurityLevel.AUTH_PRIV
        snmpv3userinfo.snmpV3Settings.authProtocol                      = authproto
        snmpv3userinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = False
        snmpv3userinfo.snmpV3Settings.haveAuthPassphrase                = True
        snmpv3userinfo.snmpV3Settings.authPassphrase                    = params['authpassword'] 
        snmpv3userinfo.snmpV3Settings.privProtocol                      = privproto
        snmpv3userinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = False
        snmpv3userinfo.snmpV3Settings.havePrivPassphrase                = True
        snmpv3userinfo.snmpV3Settings.privPassphrase                    = params['privpassword']

    if functiondebug:
        print('Proposed new SNMP v3 settings are:')
        print(snmpv3userinfo.snmpV3Settings)

    print('Updating ... ', end='', flush=True)
    rc = snmpv3userproxy.updateAccountFull('', snmpv3userinfo)
    if rc == 0:
        print('done')
    else:
        print('')
        print('An error occurred - updateAccountFull method return code = {}'.format(rc))

    if functiondebug:
        snmpv3userinfo = snmpv3userproxy.getInfo()
        print('Settings now in place are:')
        print(snmpv3userinfo.snmpV3Settings)

    return
    
########################################################################

def readhostfile(hostfile, hostfilename, params):
    global progname

    errorcount = 0

    linenum = 0

    for line in hostfile:
        linenum += 1

        line = line.rstrip()

        if line == '':
            continue

        if line[0] == '#':
            continue

        words = line.split()

        if len(words) == 0:
            continue

        host = words[0]

        setsnmpservice(host, params)

        setsnmpuser(host, params)

    return errorcount

########################################################################

def main():
    global progname

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='name of config file', default=DEFAULT_CONFIG_FILENAME)
    parser.add_argument('--host',   help='name of hosts file', default=DEFAULT_HOST_FILENAME)

    args = parser.parse_args()

    configfilename = args.config
    hostfilename = args.host

    try:
        configfile = open(configfilename, 'r', encoding='utf-8')
    except IOError:
        print('{}: unable to open config file "{}" for reading'.format(progname, configfilename), file=sys.stderr)
        sys.exit()

    errorcount, params = readconfigfile(configfile, configfilename)

    configfile.close()

    if errorcount > 0:
        sys.exit(1)

    errorcount = validparams(params)

    if errorcount > 0:
        sys.exit(1)

    ### print(params)

    try:
        hostfile = open(hostfilename, 'r', encoding='utf-8')
    except IOError:
        print('{}: unable to open host file "{}" for reading'.format(progname, hostfilename), file=sys.stderr)
        sys.exit()

    errorcount = readhostfile(hostfile, hostfilename, params)

    hostfile.close()

    if errorcount > 0:
        sys.exit(1)

    return 0

########################################################################

progname = os.path.basename(sys.argv[0])

sys.exit(main())

# end of file
