# Log4j fix

This solution provides a fix for the following CVEs:
* CVE-2021-44228
* CVE-2021-4104
* CVE-2021-45046

Tthis script scans the systems by the following rules
  * scans for all log4j*.jar files in first part,
  * scans for all potential Java Archive files and check if the log4j related stuff is embedded in

Depending on founded version, it will remove the appropriate class from the Java Archive. 

The script in it's native way just generates the remedation instructions (command by command) for the system it's been run on.


## Fix for log4j (>=2.10)

This is probably covered by removing the classes from the Java Archives. To be sure, system-wide variable disabling the JdniLookups might be the good idea anyway.

To mittigate with this issue for these log4j versions, you have to ensure that JVM will run with the appropriate variable. This could be achieved either by modifing all the JVM config or (easier) by introduce system-side variable which enforce this by following:

```
echo "export LOG4J_FORMAT_MSG_NO_LOOKUPS=true" > /etc/profile.d/log4j.sh

# For system with systemd:
if [ -e /etc/systemd/system.conf ]; then
        if [[ ! $(fgrep LOG4J_FORMAT_MSG_NO_LOOKUPS /etc/systemd/system.conf) ]]; then
        echo "DefaultEnvironment=\"LOG4J_FORMAT_MSG_NO_LOOKUPS=true\"" >> /etc/systemd/system.conf
        fi
fi
```

**IMPORTANT NOTE: ** In case of systemd init is in place, you have to reboot whole server to activate this! For SystemV init derivates, restart of the application should be sufficient.

## Usage

Script could be trigerred by the following ways:
1. ./log4j.sh (scans whole system)
2. ./log4j.sh /directory/path (scans just particular directory)

Once done, following files are created:
- /tmp/log4j.SCANNED - just handler which proves than scan was succesfull (I'm using it when gathering the data back to bu sure they are consistant)
- /tmp/log4j.dat - this file contains the scanned data, including the remediation instructions

### Remediation

```
cat /tmp/log4j.dat |sh
```

After the instructions are invocated then, application restart is needed - in some cases, reboot of whole server could be the more faster approach.


## Author

Martin Sukany (Martin.Sukany@kyndryl.com; slack: #suky57)
