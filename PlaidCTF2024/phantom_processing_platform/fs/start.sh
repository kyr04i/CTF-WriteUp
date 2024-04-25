#!/bin/bash

SENSOR_PORT=1337

socat TCP-LISTEN:${SENSOR_PORT},reuseaddr,fork EXEC:"setsid ./handle_connection.sh"
