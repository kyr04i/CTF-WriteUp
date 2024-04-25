enc=b'^8rq9{Vd:VyesV~9|emVph6t'
enc=list(enc)
dec=[]
for i in enc:
    dec.append(i^9)
  
print(''.join(chr(i) for i in dec))