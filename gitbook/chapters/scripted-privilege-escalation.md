# Scripted Privilege Escalation

Before moving to **[Root Cause Analysis](root-cause-analysis.md)** chapter, let's first see how we can achieve **privilege escalation** using custom **GDB** script.

In **[Build Kernel](vulnerability-trigger.md#build-kernel)** and **[Boot Kernel](vulnerability-trigger.md#boot-kernel)**, you learned how to **build** and **boot** a custom kernel in **emulator**.

**GDB** supports python scripting, let's see how we can use python for **debugging automation**.


## Kernel Debugging {#kernel-debugging}

**emulator** uses `qemu` in the background and it supports **gdbserver** known as **gdbstub**. We can use it to do **kernel debugging**, if we have the `vmlinux` file for the corresponding kernel.

Let's boot the custom kernel that we built, but this time, with **gdbstub** enabled. For this we will need two terminal windows.

In the first window, we will run the **emulator** with **gdbstub** enabled.

```bash
ashfaq@hacksys:~/workshop$ emulator -show-kernel -no-snapshot -wipe-data -avd CVE-2019-2215 -kernel ~/workshop/android-4.14-dev/out/kasan/dist/bzImage -qemu -s -S
```


> **Note:** `-qemu` arguments states that the next parameters will be passed to underlying `qemu` emulator. `-s` argument is for `qemu` which is a shorthand for `-gdb tcp::1234`. `-S` argument makes `qemu` to wait for the debugger to connect.


In the second window, we will use **GDB** to attach to the `qemu` instance.

```bash
ashfaq@hacksys:~/workshop$ gdb -quiet ~/workshop/android-4.14-dev/out/kasan/dist/vmlinux -ex 'target remote :1234'
```

```
GEF for linux ready, type `gef' to start, `gef config' to configure
77 commands loaded for GDB 8.2 using Python engine 2.7
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from /home/ashfaq/workshop/android-4.14-dev/out/kasan/dist/vmlinux...done.
Remote debugging using :1234
warning: while parsing target description (at line 1): Could not load XML document "i386-64bit.xml"
warning: Could not load XML target description; ignoring
0x000000000000fff0 in exception_stacks ()
gef> c
Continuing.
```

Once the **Android** is booted completely, we can open the third terminal window and launch `adb` shell.

```bash
ashfaq@hacksys:~/workshop$ adb shell
generic_x86_64:/ $ uname -a
Linux localhost 4.14.150+ #1 repo:q-goldfish-android-goldfish-4.14-dev SMP PREEMPT Sat Apr x86_64
generic_x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
generic_x86_64:/ $ 
generic_x86_64:/ $ dmesg
dmesg: klogctl: Permission denied
1|generic_x86_64:/ $ 
1|generic_x86_64:/ $ pidof sh                                                                                        
7474
generic_x86_64:/ $
```

In the `adb` shell window, we can see that currently we are running with `uid=2000(shell) gid=2000(shell)` and does not have rights to see `dmesg`. To read `dmesg`, we will need **root** privileges.

`pidof sh` is `7474`, our goal is to use **kernel debugging** with **GDB** automation to do privilege escalation and give the **root** privileges to this `sh` process.

Now, in the **GDB** window press **CTRL+C** to break in **GDB** so that we can issue some commands.

You can find `root-me.py` which is an automation built on top of `GDB` python scripting in `~/workshop/gdb`.

```py
# -*- coding: utf-8 -*-

import gdb
import struct

[...]

def write32(address, value):
    gdb.selected_inferior().write_memory(address, struct.pack("<i", value), 4)

def write64(address, value):
    gdb.selected_inferior().write_memory(address, struct.pack("<Q", value), 8)

def root_me(task):
    cred = task["cred"]

    uid = cred["uid"]
    gid = cred["gid"]
    suid = cred["suid"]
    sgid = cred["sgid"]
    euid = cred["euid"]
    egid = cred["egid"]
    fsuid = cred["fsuid"]
    fsgid = cred["fsgid"]

    securebits = cred["securebits"]

    cap_inheritable = cred["cap_inheritable"]
    cap_permitted = cred["cap_permitted"]
    cap_effective = cred["cap_effective"]
    cap_bset = cred["cap_bset"]
    cap_ambient = cred["cap_ambient"]

    write32(uid.address, 0)    # GLOBAL_ROOT_UID = 0
    write32(gid.address, 0)    # GLOBAL_ROOT_GID = 0
    write32(suid.address, 0)   # GLOBAL_ROOT_UID = 0
    write32(sgid.address, 0)   # GLOBAL_ROOT_GID = 0
    write32(euid.address, 0)   # GLOBAL_ROOT_UID = 0
    write32(egid.address, 0)   # GLOBAL_ROOT_GID = 0
    write32(fsuid.address, 0)  # GLOBAL_ROOT_UID = 0
    write32(fsgid.address, 0)  # GLOBAL_ROOT_GID = 0

    write32(securebits.address, 0)  # SECUREBITS_DEFAULT = 0

    write64(cap_inheritable.address, 0)           # CAP_EMPTY_SET = 0x0000000000000000
    write64(cap_permitted.address, 0x3FFFFFFFFF)  # CAP_FULL_SET = 0x0000003FFFFFFFFF
    write64(cap_effective.address, 0x3FFFFFFFFF)  # CAP_FULL_SET = 0x0000003FFFFFFFFF
    write64(cap_bset.address, 0x3FFFFFFFFF)       # CAP_FULL_SET = 0x0000003FFFFFFFFF
    write64(cap_ambient.address, 0)               # CAP_EMPTY_SET = 0x0000000000000000

[...]

def disable_selinux_enforcing():
    selinux_enforcing = gdb.parse_and_eval("selinux_enforcing")
    write32(selinux_enforcing.address, 0)

[...]

class RootByPidFunc(gdb.Command):
    def __init__(self):
        super(RootByPidFunc, self).__init__("root-by-pid", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if not argv:
            raise gdb.GdbError("PID not provided")

        pid = int(argv[0])
        task = get_task_by_pid(pid)

        if not task:
            raise gdb.GdbError("No task of PID: {0}".format(pid))

        [...]
        root_me(task)
        [...]
        disable_selinux_enforcing()
        [...]

# register the commands
[...]
RootByPidFunc()
```

Let's load this file in **GDB** and give **root** privilege to `sh` process with pid `7474`.

```
gef> c
Continuing.
^C
Thread 1 received signal SIGINT, Interrupt.
native_safe_halt () at /home/ashfaq/workshop/android-4.14-dev/goldfish/arch/x86/include/asm/irqflags.h:61
61	}
gef> source ~/workshop/gdb/root-me.py 
gef> root-by-pid 7474
[+] Rooting
    [*] PID: 0x1d32
    [*] Cmd: sh
    [*] Task: 0xffff888033521d40
[+] Patching cred
    [*] Cred: 0xffff8880580f1480
[+] Patching selinux_enforcing
    [*] selinux_enforcing: 0xffffffff82b34028 <selinux_enforcing>
[*] Rooting complete
gef> c
Continuing.
```

Let's verify if `sh` process is having **root** privileges.

```bash
generic_x86_64:/ $ dmesg
dmesg: klogctl: Permission denied
1|generic_x86_64:/ $ 
1|generic_x86_64:/ $ id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
generic_x86_64:/ $
generic_x86_64:/ $ dmesg | head                                                                                    
[   34.036876] apexd: Scanning /product/apex for embedded keys
[   34.037889] apexd: ... does not exist. Skipping
[   34.038743] apexd: Populating APEX database from mounts...
[   34.040108] apexd: Failed to walk /product/apex : Can't open /product/apex for reading : No such file or directory
[   34.042497] apexd: Found "/apex/com.android.tzdata@290000000"
[   34.043586] apexd: Found "/apex/com.android.runtime@1"
[   34.044542] apexd: 2 packages restored.
[   34.054885] type=1400 audit(1586624810.629:5): avc: denied { getattr } for comm="ls" path="/data/misc" dev="vdc" ino=13 scontext=u:r:toolbox:s0 tcontext=u:object_r:unlabeled:s0 tclass=dir permissive=0
[   34.057660] type=1400 audit(1586624810.659:6): avc: denied { ioctl } for comm="init" path="/data/vendor" dev="vdc" ino=21 ioctlcmd=0x6615 scontext=u:r:init:s0 tcontext=u:object_r:unlabeled:s0 tclass=dir permissive=0
[   34.073716] type=1400 audit(1586624810.659:6): avc: denied { ioctl } for comm="init" path="/data/vendor" dev="vdc" ino=21 ioctlcmd=0x6615 scontext=u:r:init:s0 tcontext=u:object_r:unlabeled:s0 tclass=dir permissive=0
```

Awesome, **privilege escalation** is successful and we are going to achieve the same thing using a **kernel vulnerability**.
