# openssl_stack_standalone
Standalone and Self-sufficient header in C for openssl stack use

STACK API
The stack library provides a generic way to handle collections of objects in OpenSSL. A comparison function can be registered to sort the collection.

https://wiki.openssl.org/index.php/STACK_API

# compile & test
```
[dreg@fr33project ~/openssl_stack_standalone]# gcc -o example1 example.c
[dreg@fr33project ~/openssl_stack_standalone]# ./example1

 a: 9 - b: 3.400000

 a: 2 - b: 2.100000

 a: 9 - b: 3.400000

 a: 9 - b: 3.400000

press enter to close.
```

# TODO

* Document in the README each stack API and how to use the header.
* Remove unnecesary openssl code (a lot of useless stuff)
* Now it cant compile if you include the header from two or more sources. Make a real self-sufficient header like miniz: https://github.com/tessel/miniz/blob/master/miniz.c
