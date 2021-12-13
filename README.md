# CVE-2021-44228 Log4j fix

* this script scans the systems by the following rules
  * scans for all log4j*.jar files in first part,
  * scans for all potential Java Archive files and check if the log4j related stuff is embedded in
* If some of the above scans has findings, than it could act according the proposed solutions -- THIS SCRIPT IS INTENDED for the case, where upgrade to the latest version of log4j is not a way!
  * log4j 1.x and <= 2.10.x -- remove the vulnerable class from the classpath
  * log4j > 2.10 -- proposes to use the system-wide variable which ensure that JVM will disable the potential vulnerable functionality

The script in it's native way just generates the remedation instructions (command by command) for the system it's been run on.

## Usage

```
./log4j.sh #just provides the instructions
./log4j.sh > vulnerable 2> already_remediated
./log4j.sh |sh #also invocate the instructions
```

After the instructions are invocated then, application restart is needed - in some cases, reboot of whole server could be the more faster approach.
