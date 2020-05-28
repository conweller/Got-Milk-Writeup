# Got Milk Exploit
Connor Onweller and Sophia Freaney

## Let's see what we got here
Looks like we've got the following files:

```
7got_milk
├── gotmilk
└── libmylib.so
```
Looks we got a library `libmylib.so` and an executable called `gotmilk`.

Prolly gotta do something with that library, but lets ignore for now and try
and run `gotmilk`:

```sh
./gotmilk
```

Hmm looks like we get the following error:
```
./gotmilk: error while loading shared libraries: libmylib.so: cannot open
shared object file: No such file or directory
```

Looks like we need to specify the library path so the executable can find
`libmylib.so`. We can do this with:

```sh
export LD_LIBRARY_PATH=.
```

Now if we run `./gotmilk` we get the following output

```
Simulating loss...

No flag for you!
Hey you! GOT milk? Yes please
Your answer: Yes please

No flag for you!
```

Looks like we don't got milk.

Let try looking at this with `ltrace` to see whats going on. This will show us
what library function are being called in the executable, and what arguments
are passed into them.

```sh
ltrace ./gotmilk
```

We get the following output;

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

From this, the notable things we see 2 things:

1. Theres a lose function in `libmylib.so` which prints `No flag for you!`, we
   should checkout this library to see what else there is
2. It looks like our inputted string is passed directly into a `printf`
   statement, meaning there might be a format string vulnerability

Lets look into this stuff

### What boppin in libmylib.so?

We want to see what functions `libmylib.so` contains. We can do so with the
following command:

```sh
rabin2 -s libmylib.so
```

`rabin2` is a binary program info extractor. When we pass the `-s` flag into
the command, we specify that we want to get back a list of export symbols from
the binary.

From this we can see there's a lose function and a win function:

```
10   0x000011f8 0x000011f8 GLOBAL FUNC   49       lose
11   0x00001189 0x00001189 GLOBAL FUNC   111      win
```

This win function probably `cat`s the contents of some some file or something
like that. Lets looks for relevant strings that might contain a filename with
the following:

```sh
rabin2 -z libmylib.so
```

Output
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002002 0x00002002 8   9    .rodata ascii flag.txt
1   0x0000200b 0x0000200b 17  18   .rodata ascii \nNo flag for you!
```

Looks the filename is `flag.txt`. Since we don't have this file already lets
make one:

```sh
echo My bones > flag.txt
```

# Whats going on with all this printf stuff?

Now we want to see if the 2nd call `printf` is is print our inputted string
directly. Lets test it out by trying to pass it some `printf` flags in our
text:

With the following input:

```
Hey you! GOT milk? %x %x %x
Your answer: 64 f7f6f580 804866f
```

We get this output:
```
Your answer: 64 f7f6f580 804866f
```

Looks like we got a format string vulnerability.
