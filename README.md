# raritan-setsnmpv3

Python program using the Raritan JSON-RPC SDK to set SNMP v3 passwords.

The SNMP v3 authentication and privacy passwords can be set on one or
more Raritan PDUs using this program.  The protocols are also specified.

Handy for making bulk password changes to large numbers of PDUs during a deployment
or using to make regular password changes to comply with local security standards.

## Quick start

Edit the `snmpv3.conf` file and specify the necessary user credentials.  More help below.

Edit the `snmpv3.hosts` and put the name of one or more of your PDUs in it, one per line.

Run the Python 3 program `setsnmpv3.py`.  It should work on UNIX/Linux and Windows.

## Pre-requisites

You will need:

+ Windows or UNIX/Linux
+ A recent install of Python 3
+ The latest JSON-RPC SDK from Raritan installed
+ The Python bindings from the SDK listed in PYTHONPATH

That should be all.

## The `snmpv3.conf` configurartion file

The `snmpv3.conf` file holds the necessary information for the `setsnmpv3.py` program to work.  It
is a plain text file.  Lines beginning with a '#' character are comments and are ignored.  Blank lines
are also ignored.  Remaining lines are of the format:

```
keyword = value
```

The following keywords are recognised:

```
user
userpass
snmpuser
securitylevel
authprotocol
authpassword
privprotocol
privpassword
```

The `user` keyword specifies the username to log into the PDU with.

The `userpass` keyword specfies the password if the user specified by the `user` keyword.

The `snmpuser` keyword specifies the username on the PDU to enable SNMP v3 credentials.

The `securitylevel` keyword specifies the level of SNMP v3 to use. It can be one of:

+ `none` - no security
+ `auth` - authentication security only
+ `auth+priv` - authentication and privacy security

The `authprotocol` keyword specifies the authenication protocol to use.  It can be either `SHA-1` or `MD5`.

The `authpassword` keyword specifies the authentication pass phrase to set.

The `authprotocol` and `authpassword` keywords are required when the `securitylevel` is either `auth`
or `auth+priv'.

The `privprotocol` protocol specifies the privacy protocol to use.  It can be either 'DES' or 'AES-128'.

The `privpassword` protocol specifies the privacy pass phrase to set.

The `privprotocol` and `privpassword` keywords are required when the `securitylevel` is `auth+priv`.

An example `snmpv3.conf` file could look like:

```
#
# snmpv3.conf
#

user          = admin
userpass      = raritan
snmpuser      = admin
securitylevel = auth+priv
authprotocol  = SHA-1
authpassword  = Long-Password-1-^%
privprotocol  = DES
privpassword  = Long-Password-2-^%
```

A note on security.  Because the `snmpv3.conf` file contains passwords in plain text ensure
the file has appropriate access permissions set on it so only authorised users can access it.

## The `snmpv3.hosts` configuration file

The `snmpv3.hosts` file contains host names, one per line, of each PDU the `setsnmpv3.py` program
is to set the SNMP v3 password on.  Lines which begin with a '#' character and blank lines are 
treated as comments and are ignored.

Here is a typical `snmpv3.hosts` file:

```
#
# snmpv3.hosts
#
px3rack
192.168.8.20
px2study
```

## Running the `setsnmpv3.py` program

Put the following files:

+ setsnmpv3.py
+ snmpv3.conf
+ snmpv3.hosts

In the same directory.

On Windows open a command prompt, change to the directory and type:

```
python setsnmpv3.py
```

On UNIX/Linux open a command prompt, change to the directory and type:

```
./setsnmpv3.py
```

The `setsnmpv3.py` program will read and validate the `snmpv3.conf` configurartion file.
Next it will read lines from the `snmpv3.hosts` file and for each host naeme will
set the SNMP v3 passwords on that PDU.

If errors occur the message and sent to standard error and the programs moves on to the next
PDU in the `snmpv3.hosts` file.

## Command line options for the `setsnmpv3.py` program

The `setsnmpv3.py` program recognises some command line options.

### Command line option `--config`

The `--config` command line option allows a different configuration file.  For example if
there is a configuration file called `datahall2.conf` that has the appropriate settings
then run as:

```
python setsnmpv3.py --config datahall2.conf
```

on Windows and on UNIX/Linux run as:

```
./setsnmpv3.py --config datahall2.conf
```

The `--host` command line option allows a different host file.  For example if there is a 
host file called `secondfloor.hosts` that has the required list of host names then
run as:

```
python setsnmpv3.py --host secondfloor.hosts
```

on Windows and on UNIX/Linux run as:

```
./setsnmpv3.py --host secondfloor.hosts
```

You can specify both the `--config` and `--host` command line options if required.




------------------------------------
End of file
