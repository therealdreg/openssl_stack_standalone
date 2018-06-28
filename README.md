# openssl_stack_standalone
Standalone and Self-sufficient header in C for openssl stack use

STACK API
The stack library provides a generic way to handle collections of objects in OpenSSL. A comparison function can be registered to sort the collection.

https://wiki.openssl.org/index.php/STACK_API

# TODO

* Remove unnecesary openssl code (a lot of useless stuff)
* Now it cant compile if you include the header from two or more sources. Make a real self-sufficient header like miniz: https://github.com/tessel/miniz/blob/master/miniz.c
