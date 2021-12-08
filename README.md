# Cloudera custom alert script
Used to filter out some Cloudera alerts and forward them to SNMP trap instead using inbuilt SNMP alerting.
Should be used as [custom alert script](https://docs.cloudera.com/cloudera-manager/7.4.2/monitoring-and-diagnostics/topics/cm-alerts-script.html)
# Configuration
Every alert can be filtered by service name or keyword in alert message.
Currently only blacklisting supported and it is configured in [configuration file](./cloudera_alert_snmp.ini).

# Installation
Currently done manually, `git clone` the project or unpac downloaded tarball.

Install libraries
```
python -m pip install -r requirements.txt
```
One will need to download your Cloudera installation MIB file
```
wget https://[Cloudera hostname]/static/snmp/cm.mib
```
Or one published in Cloudera documentation
```
wget https://docs.cloudera.com/documentation/other/shared/cm.mib.txt -O cm.mib
```
And place it on the filesystem

Verify that there are generic set of MIBs is present on the system, if not install 
```
sudo yum install snmp-net-tools
```
Convert Cloudera MIB to the form acepted by `pysnmp` this example specified to work with the python 2.7 but the directory might be arbitrary chosen, just add it to the right place of the [configuration file](./cloudera_alert_snmp.ini).
```
mibdump.py --mib-source /usr/share/snmp/mibs --mib-source . --destination-directory /usr/lib/python2.7/site-packages/pysnmp/smi/mibs/ cm
```

# Bugs
There is a bug in latest released pysnmp (4.4.12)
In the pysnmp/smi/rfc1902.py line 306 should like
```
def resolveWithMib(self, mibViewController, ignoreErrors=True):
```
Patch this file using:
```
patch /usr/lib/python2.7/site-packages/pysnmp/smi/rfc1902.py rfc1902.patch
```

# Usage
Configure in Cloudera under Administration -> Alerts -> Custom Alert Script.

Disable inbuilt SNMP settings if enabled.

Put proper configuration paramenters fo SNMP trap in a [configuration file](./cloudera_alert_snmp.ini).
Add filtering if needed.
