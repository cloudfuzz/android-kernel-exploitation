# GDB Macros

These are useful **macros** that you can use during **debugging**.

```
macro define offsetof(_type, _memb) ((long)(&((_type *)0)->_memb))
```

```
macro define containerof(_ptr, _type, _memb) ((_type *)((void *)(_ptr) - offsetof(_type, _memb)))
```
