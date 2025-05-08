#! /usr/bin/python3
#
# @(!--#) @(#) setsnmpv3.py, sversion 0.1.0, fversion 017, 08-may-2025
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
### import raritan.rpc.um

########################################################################

#
# constants
#

DEFAULT_CONFIG_FILENAME = 'snmpv3.conf'
DEFAULT_HOST_FILENAME   = 'snmpv3.hosts'

########################################################################

def alllower(s):
    if s == '':
        return False

    for c in s:
        if not c.islower():
            return False

    return True

########################################################################

def dequote(s, q1, q2):
    if len(s) >= 2:
        fc = s[0]
        lc = s[-1]

        if (((fc == q1) and (lc == q1)) or ((fc == q2) and (lc == q2))):
            s = s[1:-1]

    return s

########################################################################

def detag(html):
    s = ''

    intag = False

    for c in str(html):
        if c == '<':
            intag = True
        elif c == '>':
            intag = False
        elif not intag:
            if c == '\n':
                c = ' '
            s += c

    return s.strip()

########################################################################

def error2text(error):
    if error == 1:
        text = 'Password Unchanged'
    elif error == 2:
        text = 'Password Empty'
    elif error == 3:
        text = 'Password Too Short'
    elif error == 4:
        text = 'Password Too Long'
    elif error == 5:
        text = 'Password Ctrl Chars'
    elif error == 6:
        text = 'Password Need Lower'
    elif error == 7:
        text = 'Password Need Upper'
    elif error == 8:
        text = 'Password Need Numeric'
    elif error == 9:
        text = 'Password Need Special'
    elif error == 10:
        text = 'Password In History'
    elif error == 11:
        text = 'Password Too Short For SNMP'
    elif error == 12:
        text = 'Invalid Argument'
    elif error == 13:
        text = 'Wrong Password'
    elif error == 14:
        text = 'Ssh Pubkey Data Too Large'
    elif error == 15:
        text = 'Ssh Pubkey Invalid'
    elif error == 16:
        text = 'Ssh Pubkey Not Supported'
    elif error == 17:
        text = 'Ssh RSA Pubkey Too Short'
    else:
        text = 'Unknown error code (rc={})'.format(error)

    return text

########################################################################

def readconfigfile(configfile, configfilename):
    global progname

    params = {}

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

        if not alllower(paramname):
            print('{}: line {} in config file "{}" - parameter name "{}" is not all lowercase'.format(progname, linenum, configfilename, paramname), file=sys.stderr)
            errorcount += 1
            continue

        paramvalue = line[equalpos+1:].strip()
        paramvalue = dequote(paramvalue, '"', '\'')

        if paramvalue == '':
            print('{}: line {} in config file "{}" - parameter name "{}" has a null string value'.format(progname, linenum, configfilename, paramname), file=sys.stderr)
            errorcount += 1
            continue
 
        params[paramname] = paramvalue

        ### print('>>{}<<  >>{}<<'.format(paramname, paramvalue))

    configfile.close()

    return errorcount, params

########################################################################

def validparams(params, configfilename):
    global progname

    errorcount = 0

    for p in [ 'user', 'userpass', 'snmpuser', 'securitylevel' ]:
        if p not in params:
            print('{}: parameter "{}" is required but was not specified in config file "{}"'.format(progname, p, configfilename), file=sys.stderr)
            errorcount += 1

    if errorcount > 0:
        return errorcount

    sl = params['securitylevel']

    if not sl in [ 'disable', 'none', 'auth', 'auth+priv' ]:
        print('{}: parameter "{}" has an invalid value of "{}"'.format(progname, 'securitylevel', sl), file=sys.stderr)
        errorcount += 1
        return errorcount

    if (sl == 'auth') or (sl == 'auth+priv'):
        if 'authprotocol' not in params:
            print('{}: parameter "authprotocol" required but not in config file "{}"'.format(progname, configfilename), file=sys.stderr)
            errorcount += 1

        if 'authpassword' not in params:
            print('{}: parameter "authpassword" required but not in config file "{}"'.format(progname, configfilename), file=sys.stderr)
            errorcount += 1

        if errorcount > 0:
            return errorcount

        ap = params['authprotocol'].lower()

        if not ap in [ 'sha-1', 'md5' ]:
            print('{} valid of parameter "authprotocol" invalid'.format(progname), file=sys.stderr)
            errorcount += 1

    if sl == 'auth+priv':
        if 'privprotocol' not in params:
            print('{}: parameter "privprotocol" required but not in config file "{}"'.format(progname, configfilename), file=sys.stderr)
            errorcount += 1

        if 'privpassword' not in params:
            print('{}: parameter "privpassword" required but not in config file "{}"'.format(progname, configfilename), file=sys.stderr)
            errorcount += 1

        if errorcount > 0:
            return errorcount

        pp = params['privprotocol'].lower()

        if not pp in [ 'des', 'aes-128' ]:
            print('{} valid of parameter "privprotocol" invalid'.format(progname), file=sys.stderr)
            errorcount += 1

    return errorcount

########################################################################

def setsnmpservice(host, params):
    global progname

    agent = raritan.rpc.Agent("https", host, params['user'], params['userpass'], timeout=30, disable_certificate_verification=True)

    snmpproxy = raritan.rpc.devsettings.Snmp('/snmp', agent)

    try:
        snmpconf = snmpproxy.getConfiguration()
    except (raritan.rpc.HttpException, raritan.rpc.JsonRpcErrorException) as errmsg:
        print('{}: problem getting SNMP service details'.format(progname), file=sys.stderr)
        print('{}: {}'.format(progname, detag(errmsg)), file=sys.stderr)
        return False

    updaterequired = False

    if snmpconf.v2enable != False:
        snmpconf.v2enable = False
        updaterequired = True

    if snmpconf.v3enable != True:
        snmpconf.v3enable = True
        updaterequired = True

    if updaterequired:
        try:
            snmpproxy.setConfiguration(snmpconf)
        except (raritan.rpc.HttpException, raritan.rpc.JsonRpcErrorException) as errmsg:
            print('{}: problem setting SNMP service details'.format(progname), file=sys.stderr)
            print('{}: {}'.format(progname, detag(errmsg)), file=sys.stderr)
            return False

    return True
    
########################################################################

def setsnmpuser(host, params):
    functiondebug = False

    agent = raritan.rpc.Agent("https", host, params['user'], params['userpass'], timeout=30, disable_certificate_verification=True)

    snmpuserproxy = raritan.rpc.usermgmt.User('/auth/user/{}'.format(params['snmpuser']), agent)

    try:
        snmpuserinfo = snmpuserproxy.getInfo()
    except (raritan.rpc.HttpException, raritan.rpc.JsonRpcErrorException) as errmsg:
        print('{}: problem getting SNMP user details'.format(progname), file=sys.stderr)
        print('{}: {}'.format(progname, detag(errmsg)), file=sys.stderr)
        return False

    if functiondebug:
        print('Current SNMP v3 settings are:')
        print(snmpuserinfo.snmpV3Settings)

    sl = params['securitylevel']

    if sl == 'disable':
        snmpuserinfo.snmpV3Settings.enabled                           = False
        snmpuserinfo.snmpV3Settings.secLevel                          = raritan.rpc.usermgmt.SnmpV3SecLevel.NO_AUTH_NO_PRIV
        snmpuserinfo.snmpV3Settings.authProtocol                      = raritan.rpc.usermgmt.SnmpV3AuthProto.SHA1
        snmpuserinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = True
        snmpuserinfo.snmpV3Settings.haveAuthPassphrase                = False
        snmpuserinfo.snmpV3Settings.authPassphrase                    = ''
        snmpuserinfo.snmpV3Settings.privProtocol                      = raritan.rpc.usermgmt.SnmpV3PrivProto.DES
        snmpuserinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpuserinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpuserinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'none':
        snmpuserinfo.snmpV3Settings.enabled                           = True
        snmpuserinfo.snmpV3Settings.secLevel                          = raritan.rpc.usermgmt.SnmpV3SecLevel.NO_AUTH_NO_PRIV
        snmpuserinfo.snmpV3Settings.authProtocol                      = raritan.rpc.usermgmt.SnmpV3AuthProto.SHA1
        snmpuserinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = True
        snmpuserinfo.snmpV3Settings.haveAuthPassphrase                = False
        snmpuserinfo.snmpV3Settings.authPassphrase                    = ''
        snmpuserinfo.snmpV3Settings.privProtocol                      = raritan.rpc.usermgmt.SnmpV3PrivProto.DES
        snmpuserinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpuserinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpuserinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'auth':
        ap = params['authprotocol']

        if ap.lower() == 'sha-1':
            authproto = raritan.rpc.usermgmt.SnmpV3AuthProto.SHA1
        elif ap.lower() == 'md5':
            authproto = raritan.rpc.usermgmt.SnmpV3AuthProto.MD5

        snmpuserinfo.snmpV3Settings.enabled                           = True
        snmpuserinfo.snmpV3Settings.secLevel                          = raritan.rpc.usermgmt.SnmpV3SecLevel.AUTH_NO_PRIV
        snmpuserinfo.snmpV3Settings.authProtocol                      = authproto
        snmpuserinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = False
        snmpuserinfo.snmpV3Settings.haveAuthPassphrase                = True
        snmpuserinfo.snmpV3Settings.authPassphrase                    = params['authpassword'] 
        snmpuserinfo.snmpV3Settings.privProtocol                      = raritan.rpc.usermgmt.SnmpV3PrivProto.DES
        snmpuserinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = True
        snmpuserinfo.snmpV3Settings.havePrivPassphrase                = False
        snmpuserinfo.snmpV3Settings.privPassphrase                    = ''
    elif sl == 'auth+priv':
        ap = params['authprotocol']

        if ap.lower() == 'sha-1':
            authproto = raritan.rpc.usermgmt.SnmpV3AuthProto.SHA1
        elif ap.lower() == 'md5':
            authproto = raritan.rpc.usermgmt.SnmpV3AuthProto.MD5

        pp = params['privprotocol']

        if pp.lower() == 'des':
            privproto = raritan.rpc.usermgmt.SnmpV3PrivProto.DES
        elif pp.lower() == 'aes-128':
            privproto = raritan.rpc.usermgmt.SnmpV3PrivProto.AES128
       
        snmpuserinfo.snmpV3Settings.enabled                           = True
        snmpuserinfo.snmpV3Settings.secLevel                          = raritan.rpc.usermgmt.SnmpV3SecLevel.AUTH_PRIV
        snmpuserinfo.snmpV3Settings.authProtocol                      = authproto
        snmpuserinfo.snmpV3Settings.usePasswordAsAuthPassphrase       = False
        snmpuserinfo.snmpV3Settings.haveAuthPassphrase                = True
        snmpuserinfo.snmpV3Settings.authPassphrase                    = params['authpassword'] 
        snmpuserinfo.snmpV3Settings.privProtocol                      = privproto
        snmpuserinfo.snmpV3Settings.useAuthPassphraseAsPrivPassphrase = False
        snmpuserinfo.snmpV3Settings.havePrivPassphrase                = True
        snmpuserinfo.snmpV3Settings.privPassphrase                    = params['privpassword']

    if functiondebug:
        print('Proposed new SNMP v3 settings are:')
        print(snmpuserinfo.snmpV3Settings)

    try:
        rc = snmpuserproxy.updateAccountFull('', snmpuserinfo)
    except (raritan.rpc.HttpException, raritan.rpc.JsonRpcErrorException) as errmsg:
        print('{}: problem setting SNMP user details'.format(progname), file=sys.stderr)
        print('{}: {}'.format(progname, detag(errmsg)), file=sys.stderr)
        return False

    if rc != 0:
        print('{}: non-zero return code when setting SNMP user details (rc={})'.format(progname, rc), file=sys.stderr)
        print('{}: {}'.format(progname, error2text(rc)), file=sys.stderr)
        return False

    if functiondebug:
        snmpuserinfo = snmpuserproxy.getInfo()
        print('Settings now in place are:')
        print(snmpuserinfo.snmpV3Settings)

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

        print('Configuring SNMP v3 on host "{}"'.format(host))

        if setsnmpservice(host, params) == False:
            errorcount += 1
        else:
            if setsnmpuser(host, params) == False:
                errorcount += 1
            else:
                print('Done')

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

    errorcount = validparams(params, configfilename)

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
