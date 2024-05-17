#!/bin/sh

socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"./challenge"

