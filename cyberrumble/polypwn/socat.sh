#!/bin/sh

socat TCP-LISTEN:4140,reuseaddr,fork EXEC:"./chall.py",stderr
