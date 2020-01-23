# raritan-setsnmpv3

Python program using the Raritan JSON-RPC SDK to set SNMP v3 passwords.

ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!!

ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!!

ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!!

ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!!

ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!! ATTENTION!!!

This code is currently in Beta with minimal error checking.  Even
a mispelt or non-existant hostname will break it!  Don't worry though,
fixing this is high on my to do list :-]

The SNMP v3 authentication and privacy passwords can be set on one or
more Raritan PDUs using this program.  The protocols are also specified.

Handy to set up the passwords before importing the PDUs into a DCIM
package like Power IQ or dcTrack from Sunbird Software.

## Quick start

Edit the `snmpv3.conf` file and specify the necessary user credentials.  More help below.

Edit the `snmpv3.hosts` and put the name of one or more of your PDUs in it, one per line.

Run the Python 3 program `setsnmpv3.py`.  It should work on UNIX/Linux and Windows.

## Pre-requisites

You will need:

+ Windows or UNIX/Linux
+ A recent install of Python 3
+ The latest JSON-RPC SDK from Raritan installed
+ The Python bindings fro mthe SDK listed in PYTHONPATH

That should be all.

## to be completed ...

------------------------------------
End of file
