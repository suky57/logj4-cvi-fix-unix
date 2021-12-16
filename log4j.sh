#!/bin/ksh

LANG=C
IFS=$'\n'

_myPath=$1
_cmd_zip=zip
_cmd_unzip=unzip

# VIOS check
if [ -e "/usr/ios/cli/ioscli" ]; then
    _cmd_zip=/nim/tools/zip
    _cmd_unzip=/nim/tools/unzip
fi

# The defaults rear its ugly head again: ksh88
[ $(uname -s) == "AIX" ] && unset IFS

echo "#######################################################"
if [ -n "$_myPath" ] && [ -d "$_myPath" ]; then
    echo "# Searching dir '$_myPath' for log4j JAR files ..."
    data=$(find $_myPath -xdev -type f -name "log4j*.jar")
elif [ -n "$_myPath" ]; then
    echo "# Specified dir '$_myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR files ..."
    if [ $(uname -s) == "AIX" ]; then
        data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    elif [ $(uname -s) == "Linux" ]; then
        data=$(mount | grep -vE "/proc|nfs|nfs3|nfs4|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -xdev -type f -name "log4j*.jar")
    fi
fi
echo "#######################################################"
echo

for log4j in $data ; do
    version=$($_cmd_unzip -q -c ${log4j} META-INF/MANIFEST.MF |  grep -i "Implementation-Version" | perl -ne '/(\d.*\S)/ && print "$1"' |head -n1)
    if [ -z "$version" ]; then
        version=$($_cmd_unzip -q -c ${log4j} META-INF/MANIFEST.MF |  grep -i "Library-Version" | perl -ne '/(\d.*\S)/ && print "$1"' |head -n1)
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
            echo "$_cmd_zip -q -d \"${log4j}\" \"${j}\""
        done
        echo "#3) Restore the ownership: "
        echo "chown $owner:$group \"$log4j\""
    fi


    #version >= 2.0:
    if [ $(echo "$version" | grep  "^2\(\.\d+\)*") ]; then
        if [ $(echo $log4j |grep "log4j-core-") ]; then
            is_vuln=$(strings $log4j |fgrep -i "log4j/core/lookup/JndiLookup.class" | perl -ne  '/(.*)PK$/ && print "$1"')
            if [ -z "$is_vuln" ]; then
                echo "# OK: issue remediated" 1>&2
                echo "" 1>&2
                continue
            fi

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
            echo
            continue
        fi
    fi

    echo

done


echo "#########################################################################"
if [ -n "$_myPath" ] && [ -d "$_myPath" ]; then
    echo "# Searching dir '$_myPath' for log4j JAR embedded in various types of Java archives ..."
    data=$(find $_myPath -xdev -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar" | grep -v "log4j.*\.jar")
elif [ -n "$_myPath" ]; then
    echo "# Specified dir '$_myPath' doesn't exist ..."
    echo "#########################################################################"
    exit 2
else
    echo "# Searching whole system for log4j JAR embedded in various types of Java archives ..."
    if [ $(uname -s) == "AIX" ]; then
            data=$(mount | grep -vE "/proc|nfs3|nfs4|mounted|--------" | awk '{print $2}' | xargs -I{} find {} -xdev -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar"|grep -v "log4j.*\.jar")
    elif [ $(uname -s) == "Linux" ]; then
            data=$(mount | grep -vE "/proc|nfs|mounted|--------" | awk '{print $3}' | xargs -I{} find {} -xdev -type f -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" -o -name "*.aar"| grep -v "log4j.*\.jar")
    fi
fi
echo "#########################################################################"
echo

for candidate in $data; do 
    echo "# Candidate: $candidate" 1>&2
    log4js=$($_cmd_unzip -l $candidate | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class" | perl -ne  '/(.*)PK$/ && print "$1"')

    if [ -z "$log4js" ]; then
        echo "# OK: There is no log4j directly included in this archive" 1>&2
        echo 1>&2
    fi
	# match for false positives
	if [ $($_cmd_unzip -l $candidate | awk '{print $4}' | grep -iE "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class") ]; then
		continue
	fi
	
	# case of war file - very simple heuristic
	if [ $(echo $candidate |grep ".war$") ]; then
		echo "# ${candidate} -  WAR archive found" 1>&2
		matches=$($_cmd_unzip -l $candidate |grep ".*log4j.*.jar"| awk '{print $NF}')
		for match in $matches; do
			dir=$(echo $match |cut -d"/" -f1)
			echo "# Candidate inside war: $match" 1>&2
			echo "$_cmd_unzip $candidate $match -d ." 1>&2
			if [ $(strings \"$match\" | egrep -i "log4j/net/JMSAppender.class|log4j/core/lookup/JndiLookup.class" | perl -ne  '/(.*)PK$/ && print "$1"') ]; then
				echo "# match: $match":
				echo "$0 \"${dir}\" | sh"
				echo "$_cmd_zip $candidate $match"
				echo "rm -Rf \"${dir}\""
				continue
			fi
			echo "# OK: $match seems not to be violated"
			echo 1>&2
		done 
		continue
	fi

    for log4j in $log4js; do
        echo "# Candidate: $candidate"
            owner=$(ls -lad $candidate| awk '{print $3}')
            group=$(ls -lad $candidate| awk '{print $4}')
        echo "# Found class: $log4j"
                echo "#1) make an backup of $candidate"
                echo "cp -p \"${candidate}\" \"${candidate}.bak-$(date +%s)\""
                echo "#2) Removethe class from the classpath"
                echo "$_cmd_zip -q -d \"${candidate}\" \"$log4j\""
                echo "#3) Restore the ownership: "
                echo "chown $owner:$group \"$candidate\""

    echo
    done

done
