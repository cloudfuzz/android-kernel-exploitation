# -*- coding: utf-8 -*-

import gdb
import struct


#
# https://github.com/torvalds/linux/tree/master/scripts/gdb
#

def offset_of(typeobj, field):
    element = gdb.Value(0).cast(typeobj)
    return int(str(element[field].address).split()[0], 16)


def container_of(ptr, typeobj, member):
    return (ptr.cast(gdb.lookup_type("long")) - offset_of(typeobj, member)).cast(typeobj)


def task_lists():
    task_ptr_type = gdb.lookup_type("struct task_struct").pointer()
    init_task = gdb.parse_and_eval("init_task").address
    t = g = init_task

    while True:
        while True:
            yield t

            t = container_of(t["thread_group"]["next"],
                             task_ptr_type, "thread_group")
            if t == g:
                break

        t = g = container_of(g["tasks"]["next"], task_ptr_type, "tasks")
        if t == init_task:
            return


def get_task_by_pid(pid):
    for task in task_lists():
        if int(task["pid"]) == pid:
            return task
    return None


def read32(address):
    return struct.unpack("<i", gdb.selected_inferior().read_memory(address, 4))[0]


def read64(address):
    return struct.unpack("<Q", gdb.selected_inferior().read_memory(address, 8))[0]


def write32(address, value):
    gdb.selected_inferior().write_memory(address, struct.pack("<i", value), 4)


def write64(address, value):
    gdb.selected_inferior().write_memory(address, struct.pack("<Q", value), 8)


def root_me(task):
    """
    Root the given task

    :param task: task_struct address
    """

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


def set_selinux_task_context(task):
    """
    Set selinux task context

    :param task: task_struct address
    """

    cred = task["cred"]

    security = cred["security"]

    security_struct_t = gdb.lookup_type("struct task_security_struct").pointer()
    security_struct = security.cast(security_struct_t)

    osid = security_struct["osid"]
    sid = security_struct["sid"]

    write32(osid.address, 0x1) # SECINITSID_KERNEL = 1 = kernel
    write32(sid.address, 0x1)  # SECINITSID_KERNEL = 1 = kernel


def disable_selinux_enforcing():
    """
    Disable selinux_enforcing globally
    """

    selinux_enforcing = gdb.parse_and_eval("selinux_enforcing")

    write32(selinux_enforcing.address, 0)


class TaskListFunc(gdb.Command):
    """List all task_struct"""

    def __init__(self):
        super(TaskListFunc, self).__init__("task-list", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        task_list = task_lists()

        for task in task_list:
            gdb.write(
                "Task: {0} PID: {1} Command: {2}\n".format(
                    task, task["pid"], task["comm"].string()
                )
            )


class TaskByPidFunc(gdb.Command):
    """List task_strcut by PID"""

    def __init__(self):
        super(TaskByPidFunc, self).__init__("task-by-pid", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if not argv:
            raise gdb.GdbError("PID not provided")

        pid = int(argv[0])
        task = get_task_by_pid(pid)

        if task:
            gdb.write(
                "Task: {0} PID: {1} Command: {2}\n".format(
                    task, task["pid"], task["comm"].string()
                )
            )
        else:
            raise gdb.GdbError("No task of PID: {0}".format(pid))


class RootByPidFunc(gdb.Command):
    """Give root privilege to given PID"""

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

        gdb.write("[+] Rooting\n")
        gdb.write("    [*] PID: {0}\n".format(task["pid"]))
        gdb.write("    [*] Cmd: {0}\n".format(task["comm"].string()))
        gdb.write("    [*] Task: {0}\n".format(task))

        gdb.write("[+] Patching cred\n")
        gdb.write("    [*] Cred: {0}\n".format(task["cred"]))

        root_me(task)

        gdb.write("[+] Patching selinux_enforcing\n")
        gdb.write(
            "    [*] selinux_enforcing: {0}\n".format(
                gdb.parse_and_eval("selinux_enforcing").address
            )
        )

        disable_selinux_enforcing()

        # gdb.write("[+] Patching selinux task context\n")

        # set_selinux_task_context(task)

        gdb.write("[*] Rooting complete\n")


# register the commands
TaskListFunc()
TaskByPidFunc()
RootByPidFunc()
