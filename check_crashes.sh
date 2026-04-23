#!/bin/bash

for i in $(ls crashes)
do
	./bdclient_x64 "./crashes/"$i
	if [ $? -eq 139 ]; then
    		echo "It crashed with $i" >> crashes_log.txt 
		sleep 5s
	fi
done
