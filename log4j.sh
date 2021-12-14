#!/bin/bash

LANG=C
IFS=$'\n'

myPath=$1

echo "#######################################################"
if [ -n "$myPath" ] && [ -d "$myPath" ]; then
    echo "# Searching dir '$myPath' for log4j JAR files ..."
    data=$(find $myPath -type f -name "log4j*.jar")
elif [ -n "$myPath" ]; then
    echo "# Specified dir '$myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR files ..."
    if [[ $(uname -s) == "AIX" ]]; then
        data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    elif [[ $(uname -s) == "Linux" ]]; then
        data=$(mount | grep -vE "/proc|nfs|nfs3|nfs4|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    fi
fi
echo "#######################################################"
echo

for log4j in $data ; do
    version=$(unzip -q -c ${log4j} META-INF/MANIFEST.MF |  grep -i "Implementation-Version" | perl -ne '/(\d.*\S)/ && print "$1"' |head -n1)
    if [ -z "$version" ]; then
        version=$(unzip -q -c ${log4j} META-INF/MANIFEST.MF |  grep -i "Library-Version" | perl -ne '/(\d.*\S)/ && print "$1"' |head -n1)
    fi
    owner=$(ls -lad $log4j| awk '{print $3}')
    group=$(ls -lad $log4j| awk '{print $4}')
    echo "# ${log4j},${version}" 1>&2
    echo "# Ownership: $owner:$group" 1>&2

    # thrown warning if version couldn't be determined
    if [ -z $version ]; then
        echo "# WARNING: from this jar file, version couldn't be determined - MANIFEST is missing inside!"
        echo
        continue
    fi

    # version 1.x stream
    if [ $(echo $version |grep "^1\.") ]; then
        is_vuln=$(strings $log4j |fgrep -i "log4j/net/JMSAppender.class" | perl -ne  '/(.*)PK$/ && print "$1"')
        if [ -z "$is_vuln" ]; then
            echo "# OK: issue remediated" 1>&2
            echo "" 1>&2
            echo "" 1>&2
            continue
        fi

        echo "# ${log4j},${version}"
        echo "# Ownership: $owner:$group"
        echo "# vers 1.x: class should be removed"
        echo "#1) make an backup of $log4j"
        echo "cp -p \"${log4j}\" \"${log4j}.bak-$(date +%s)\""
        echo "#2) Remove the class from the classpath"
        for j in $is_vuln; do
            echo "zip -q -d \"${log4j}\" \"${j}\""
        done
        echo "#3) Restore the ownership: "
        echo "chown $owner:$group \"$log4j\""
    fi


    #version up to 2.10x stream:
    if [ $(echo "$version" | grep -E "^2\.[0-9]([^0-9]|$)") ]; then
        if [ $(echo $log4j |grep "log4j-core-") ]; then
            is_vuln=$(strings $log4j |fgrep -i "log4j/core/lookup/JndiLookup.class" | perl -ne  '/(.*)PK$/ && print "$1"')
            if [ -z "$is_vuln" ]; then
                echo "# OK: issue remediated" 1>&2
                echo "" 1>&2
                continue
            fi

            echo "# ${log4j},${version}"
            echo "# Ownership: $owner:$group"
            echo "# vers 2.x (lower than 2.10): class should be removed"
            echo "#1) make an backup of $log4j"
            echo "cp -p \"${log4j}\" \"${log4j}.bak-$(date +%s)\""
            echo "#2) Remove the class from the classpath"
            for j in $is_vuln; do
                echo "zip -q -d \"${log4j}\" \"${j}\""
            done
            echo "#3) Restore the ownership: "
            echo "chown $owner:$group $log4j"

        else
            echo "# OK: for version 2.x (prior to 2.10) just log4j-core module should be updated." 1>&2
            echo
            continue
        fi
    fi

    # version >=2.10 stream:
    if [ $(echo $version |grep "^2\.[1-9][0-9]") ]; then
        echo "# ${log4j},${version}"
        echo "# Ownership: $owner:$group"
        echo "# vers >= 2.10:"
        envvar=$(env | fgrep LOG4J_FORMAT_MSG_NO_LOOKUPS |cut -d= -f2)
        if [[ $envvar == "true" ]]; then
            echo "# OK: issue remediated, system-wide variable is in place."
        else
            echo "# WARNING: System-side variable LOG4J_FORMAT_MSG_NO_LOOKUPS=true MUST to be set"
        fi
    fi

    echo

done


echo "#########################################################################"
if [ -n "$myPath" ] && [ -d "$myPath" ]; then
    echo "# Searching dir '$myPath' for log4j JAR embedded in various types of Java archives ..."
    data=$(find $myPath -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar" | grep -v "log4j.*\.jar")
elif [ -n "$myPath" ]; then
    echo "# Specified dir '$myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR embedded in various types of Java archives ..."
    if [[ $(uname -s) == "AIX" ]]; then
            data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -xdev -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar"|grep -v "log4j.*\.jar")
    elif [[ $(uname -s) == "Linux" ]]; then
            data=$(mount | grep -vE "/proc|nfs|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -xdev -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar"| grep -v "log4j.*\.jar")
    fi
fi
echo "#########################################################################"
echo

for candidate in $data; do 
    echo "# Candidate: $candidate" 1>&2
    log4js=$(strings $candidate | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class" | perl -ne  '/(.*)PK$/ && print "$1"')

    if [ -z "$log4js" ]; then
        echo "# OK: There is no log4j directly included in this archive" 1>&2
        echo 1>&2
    fi
    for log4j in $log4js; do
        echo "# Candidate: $candidate"
            owner=$(ls -lad $candidate| awk '{print $3}')
            group=$(ls -lad $candidate| awk '{print $4}')
        echo "# Found class: $log4j"
                echo "#1) make an backup of $candidate"
                echo "cp -p \"${candidate}\" \"${candidate}.bak-$(date +%s)\""
                echo "#2) Removethe class from the classpath"
                echo "zip -q -d \"${candidate}\" \"$log4j\""
                echo "#3) Restore the ownership: "
                echo "chown $owner:$group \"$candidate\""

    echo
    done

done
