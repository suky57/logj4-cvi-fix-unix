#!/bin/ksh

### FUNCTIONS FOLLOW:

function process_archive {
    log4j=$1
    if [ -z $log4j ]; then
        echo "function needs at least one argument (JAR archive)"
        exit 3
    fi
    version=$($_cmd_unzip -q -c ${log4j} META-INF/MANIFEST.MF | grep -i "Implementation-Version" | perl -ne '/(\d.*\S)/ && print "$1"' | head -n1)
    if [ -z "$version" ]; then
        version=$($_cmd_unzip -q -c ${log4j} META-INF/MANIFEST.MF | grep -i "Library-Version" | perl -ne '/(\d.*\S)/ && print "$1"' | head -n1)
    fi
    owner=$(ls -lad "$log4j" | awk '{print $3}')
    group=$(ls -lad "$log4j" | awk '{print $4}')
    ls -lad "$log4j" 1>&2
    echo "# Candidate: ${log4j},${version}" 1>&2
    print -n "$log4j:$version:" >&5
    echo "# Ownership: $owner:$group" 1>&2

    # thrown warning if version couldn't be determined
    if [ -z $version ]; then
        echo "# WARNING: from this jar file, version couldn't be determined - MANIFEST is missing inside!" 1>&2
        echo 1>&2
        print -n "NO_LOG4J_VERSION_DETECTED:OK:" >&5
        echo "" >&5
        continue
    fi

    # version 1.x stream
    if [ $(echo $version | grep "^1\.") ]; then
        is_vuln=$(strings $log4j | fgrep -i "log4j/net/JMSAppender.class" | perl -ne '/(.*)PK$/ && print "$1"')
        if [ -z "$is_vuln" ]; then
            echo "# OK: issue remediated" 1>&2
            print -n "OK:" >&5
            echo "" >&5
            echo "" 1>&2
            return 1
        fi

        echo "# ${log4j},${version}"
        print -n "NOK:" >&5
        echo "" >&5
        echo "# Ownership: $owner:$group"
        echo "# vers 1.x: class should be removed"
        echo "#1) make an backup of $log4j"
        echo "cp -p \"${log4j}\" \"${log4j}.bak-$(date +%s)\""
        echo "#2) Remove the class from the classpath"
        for j in $is_vuln; do
            echo "$_cmd_zip -q -d \"${log4j}\" \"${j}\""
        done
        echo "#3) Restore the ownership: "
        echo "chown $owner:$group \"$log4j\""
    fi

    #version >= 2.0:
    if [ $(echo "$version" | grep "^2\.\([0-9]\|1[0-6]\)\(\.[0-9]\+\)*$") ]; then
        if [ $(echo $log4j | grep "log4j-core-") ]; then
            is_vuln=$(strings $log4j | fgrep -i "log4j/core/lookup/JndiLookup.class" | perl -ne '/(.*)PK$/ && print "$1"')
            if [ -z "$is_vuln" ]; then
                echo "# OK: issue remediated" 1>&2
                print -n "OK:" >&5
                echo "" >&5
                echo "" 1>&2
                return 1
            fi

            print -n "NOK:" >&5
            print -n "" >&5
            echo "# ${log4j},${version}"
            echo "# Ownership: $owner:$group"
            echo "# vers 2.x: class should be removed"
            echo "#1) make an backup of $log4j"
            echo "cp -p \"${log4j}\" \"${log4j}.bak-$(date +%s)\""
            echo "#2) Remove the class from the classpath"
            for j in $is_vuln; do
                echo "$_cmd_zip -q -d \"${log4j}\" \"${j}\""
            done
            echo "#3) Restore the ownership: "
            echo "chown $owner:$group $log4j"

        else
            echo "# OK: for version 2.x  just log4j-core module should be updated." 1>&2
            echo "" 1>&2
            print -n "OK:" >&5
	    echo "" >&5
            return 1
        fi
    fi

    echo "# NOK - file is violated!" 1>&2
    echo "" 1>&2
    echo "" >&5

}

### CODE FOLLOWS

LANG=C
IFS=$'\n'

_myPath=$1
_myLogFile="/tmp/log4j.dat"
_myErrorLogFile="/tmp/log4j.err"
_myCSVFile="/tmp/log4j.csv"
_myLockFile="/tmp/log4j.lock"
_myScannedFile="/tmp/log4j.SCANNED"
_myNFS="/tmp/log4j_NFS"
_cmd_zip=zip
_cmd_unzip=unzip

test -f ${_myLogFile} && rm -f ${_myLogFile}

# VIOS check
if [ -e "/usr/ios/cli/ioscli" ]; then
    _cmd_zip=/nim/tools/zip
    _cmd_unzip=/nim/tools/unzip
else
    # if not VIO, ensure the output is collected in the logfile
    exec 3>&1
    exec 4>&2
    exec 5>${_myCSVFile}
    exec 1>"${_myLogFile}"
    exec 2>"${_myErrorLogFile}"

    # mount the remote NFS
    test ! -d ${_myNFS} && mkdir ${_myNFS}
    mount dbkpinst01s1.rze.de.db.com:/export/mksysb/log4j ${_myNFS}

fi

# Check the lock file, if exists, exit now!
if [ -f ${_myLockFile} ]; then
	echo "${_myLockFile} exists! Exitting ... "
	exit 255
else
	touch ${_myLockFile}
fi

# The defaults rear its ugly head again: ksh88
if [ "$(uname -s)" == "AIX" ] || [ "$(uname -s)" == "SunOS" ]; then
    unset IFS
fi

test -f ${_myScannedFile} && rm -f ${_myScannedFile}

echo "#######################################################"
if [ -n "$_myPath" ] && [ -d "$_myPath" ]; then
    echo "# Searching dir '$_myPath' for log4j JAR files ..."
    data=$(find $_myPath -type f -name "log4j*.jar")
elif [ -n "$_myPath" ]; then
    echo "# Specified dir '$_myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR files ..."
    if [ "$(uname -s)" == "AIX" ]; then
        data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    elif [ "$(uname -s)" == "Linux" ]; then
        data=$(mount | grep -vE "/proc|nfs|nfs3|nfs4|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    elif [ "$(uname -s)" == "SunOS" ]; then
        data=$(mount | egrep -v "^/proc|^/system|^/platform|^/dev|^/[rs]pool|^/etc/mnttab|^/etc/svc/volatile|^/etc/dfs/sharetab|\ remote/" | awk '{print $1}' | xargs -I{} find {} -type f -xdev -name "log4j*.jar")
    fi

fi

echo "#######################################################"
echo

for log4j in $data; do
    process_archive $log4j
done

echo "#########################################################################"
if [ -n "$_myPath" ] && [ -d "$_myPath" ]; then
    echo "# Searching dir '$_myPath' for log4j JAR embedded in various types of Java archives ..."
    data=$(find $_myPath -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar" | grep -v "log4j.*\.jar")
elif [ -n "$_myPath" ]; then
    echo "# Specified dir '$_myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR embedded in various types of Java archives ..."
    if [ "$(uname -s)" == "AIX" ]; then
        data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -type f -xdev \( -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar" \) -a \! -name "log4j.*\.jar")
    elif [ "$(uname -s)" == "Linux" ]; then
        data=$(mount | grep -vE "/proc|nfs|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -type f -xdev -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar" | grep -v "log4j.*\.jar")
    elif [ "$(uname -s)" == "SunOS" ]; then
        data=$(mount | egrep -v "^/proc|^/system|^/platform|^/dev|^/[rs]pool|^/etc/mnttab|^/etc/svc/volatile|^/etc/dfs/sharetab|\ remote/" | awk '{print $1}' | xargs -I{} find {} -type f -name "log4j*.jar")
    fi

fi
echo "#########################################################################"
echo
for candidate in $data; do
    echo "# Candidate: $candidate" 1>&2
    print -n "$candidate:SCAN_FOR_EMBEDED_LOG4J_NO_VERSION_HERE:" >&5
    log4js=$($_cmd_unzip -l $candidate | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class" | perl -ne '/(.*)PK$/ && print "$1"')
    # match for false positives
    if [ $($_cmd_unzip -l $candidate | awk '{print $4}' | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class") ]; then
        echo "# OK: in this archive, no log4j occurence" 1>&2
        echo "" 1>&2
        print -n "OK:" >&5
        echo "" >&5
        continue
    fi

    owner=$(ls -lad "$candidate" | awk '{print $3}')
    group=$(ls -lad "$candidate" | awk '{print $4}')
    ls -lad "$candidate" 1>&2

    # case of war file - very simple heuristic
    if [ $(echo $candidate | grep ".war$") ]; then
        matches=$($_cmd_unzip -l $candidate | grep ".*log4j.*.jar" | awk '{print $NF}')
        for match in $matches; do
            dir=$(echo $match | cut -d"/" -f1)
            echo "# Candidate inside war: $match" 1>&2
            $_cmd_unzip "$candidate" "$match" -d . 1>&2
            if [ $(strings $match | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class" | perl -ne '/(.*)PK$/ && print "$1"') ]; then
                echo "# $candidate($match)"
                print -n "NOK:" >&5
                echo "" >&5
                echo "cp -p \"${candidate}\" \"${candidate}.bak-$(date +%s)\""
                echo "$_cmd_unzip \"$candidate\" \"$match\" -d ."
                process_archive $match
                echo "$_cmd_zip -ur \"$candidate\" \"$match\""
		echo "chown $owner:$group \"$candidate\""
                echo "rm -Rf \"${dir}\"" # commented out for backup purposes
                echo ""
                continue
            fi
            rm -Rf "${dir}"

        done
    fi
    if [ $(echo $candidate | grep ".war$") ]; then
        echo "# OK: $match seems not to be violated" 1>&2
        echo "" 1>&2
        print -n "OK:" >&5
        echo "" >&5
        continue
    fi

    for log4j in $log4js; do
        echo "# $candidate"
        owner=$(ls -lad $candidate | awk '{print $3}')
        group=$(ls -lad $candidate | awk '{print $4}')
        echo "# Found class: $log4j"
        echo "#1) make an backup of $candidate"
        echo "cp -p \"${candidate}\" \"${candidate}.bak-$(date +%s)\""
        echo "#2) Removethe class from the classpath"
        echo "$_cmd_zip -q -d \"${candidate}\" \"$log4j\""
        echo "#3) Restore the ownership: "

        print -n "NOK:" >&5
        echo "" >&5
    done
    echo "" 1>&2
    print -n "OK:" >&5
    echo "" >&5
done

echo "#===$(date '+%F %H:%M')"
echo "#===Uptime: $(uptime)"
touch ${_myScannedFile}

# Transfer data to NFS
if [ ! -e "/usr/ios/cli/ioscli" ]; then
    cp ${_myLogFile} ${_myNFS}/$(hostname)_vuln
    cp ${_myErrorLogFile} ${_myNFS}/$(hostname)_rem
    cp ${_myCSVFile} ${_myNFS}/$(hostname)_csv
    umount ${_myNFS}
fi

# remove lockfile
rm -f ${_myLockFile}
