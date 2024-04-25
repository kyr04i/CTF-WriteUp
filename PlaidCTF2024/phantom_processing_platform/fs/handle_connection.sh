#!/bin/bash

socket_path=$(mktemp /tmp/sockets/socket_XXXXXX)
/processor_arm "$socket_path" > /dev/null 2>&1 &

sleep 0.1  

/sensor_arm "$socket_path" 