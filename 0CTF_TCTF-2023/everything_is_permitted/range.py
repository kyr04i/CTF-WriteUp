#!/usr/bin/python
# -*- coding:utf-8 -*-

import os

result = []

for i in range(100):
    result += [os.popen('./vdso_addr').read()[:-1]]
    
sorted_result = sorted(result)

for v in sorted_result:
    print(v)
    
    