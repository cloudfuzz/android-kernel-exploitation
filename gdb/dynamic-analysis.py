# -*- coding: utf-8 -*-
#
#   #####                              #######                      
#  #     # #       ####  #    # #####  #       #    # ###### ###### 
#  #       #      #    # #    # #    # #       #    #     #      #  
#  #       #      #    # #    # #    # #####   #    #    #      #   
#  #       #      #    # #    # #    # #       #    #   #      #    
#  #     # #      #    # #    # #    # #       #    #  #      #     
#   #####  ######  ####   ####  #####  #        ####  ###### ###### 
#                                                      @HackSysTeam
#

import gdb


def get_current_task():
    per_cpu_offset = gdb.parse_and_eval("__per_cpu_offset[0]")
    current_task_offset = gdb.parse_and_eval("current_task").address

    current_task = gdb.parse_and_eval(
        "*(struct task_struct *)*(long *){0}".format(
            long(per_cpu_offset) + long(current_task_offset))
    )
    return current_task


def get_current_proc_comm():
    current_task = get_current_task()
    return current_task["comm"].string()


binder_thread_address = None

def set_dump_binder_thread(parameters):
    global binder_thread_address

    binder_thread_address = parameters["thread"]
    gdb.execute("x/51gx {0}".format(binder_thread_address))
    gdb.write("\n")


def dump_binder_thread(parameters):
    if not binder_thread_address:
        return
    
    if long(binder_thread_address) + 0xA0 == parameters["wq_head"]:
        gdb.execute("x/51gx {0}".format(binder_thread_address))
        gdb.write("\n")


class EnterBp(gdb.Breakpoint):
    def __init__(
        self, proc_cmd, entry_symbol, param_list=[],
        exit_symbol=None, break_at_entry=False, entry_callback=None,
        break_at_exit=False, exit_callback=None, set_exit_bp = False
    ):
        super(EnterBp, self).__init__(entry_symbol)

        self.silent = True
        self.proc_cmd = proc_cmd
        self.function_name = entry_symbol
        self.function_params = param_list
        self.exit_symbol = exit_symbol
        self.break_at_entry = break_at_entry
        self.entry_callback = entry_callback
        self.break_at_exit = break_at_exit
        self.exit_callback = exit_callback
        self.set_exit_bp = set_exit_bp
        self.exit_bp_already_set = False
        self.parameter = {}

    def stop(self):
        is_right_process = False

        if self.proc_cmd in get_current_proc_comm():
            is_right_process = True

        if not is_right_process:
            return False
        
        for i, param_name in enumerate(self.function_params):
            self.parameter[param_name] = gdb.newest_frame().read_var(param_name)

        # build the parameter value list
        params = ""
        param_length = len(self.parameter)

        for i, (key, value) in enumerate(self.parameter.items()):
            tmp = "{key}={value}".format(key=key, value=value)
            params += tmp

            if not i == param_length - 1:
                params += ", "

        # print the function name and the parameters with their values
        gdb.write(
            "{function}({param})(enter)\n".format(
                function=self.function_name, param=params
            )
        )

        # call the entry callback
        if self.entry_callback:
            self.entry_callback(self.parameter)
        
        # set the exit breakpoint
        if self.set_exit_bp and not self.exit_bp_already_set:
            ExitBp(
                proc_cmd=self.proc_cmd, entry_symbol=self.function_name,
                exit_symbol=self.exit_symbol, params=self.parameter,
                break_at_exit=self.break_at_exit, exit_callback=self.exit_callback
            )
            self.exit_bp_already_set = True

        # should we break in debugger
        return self.break_at_entry


class ExitBp(gdb.Breakpoint):
    def __init__(
        self, proc_cmd, entry_symbol, exit_symbol, params={},
        break_at_exit=False, exit_callback=None,
    ):
        super(ExitBp, self).__init__(exit_symbol)

        self.silent = True
        self.proc_cmd = proc_cmd
        self.entry_symbol = entry_symbol
        self.exit_symbol = exit_symbol
        self.parameter = params
        self.break_at_exit = break_at_exit
        self.exit_callback = exit_callback
    
    def stop(self):
        is_right_process = False

        if self.proc_cmd in get_current_proc_comm():
            is_right_process = True

        if not is_right_process:
            return False

        gdb.write(
            "{entry}_{exit}(exit)\n".format(
                entry=self.entry_symbol, exit=self.exit_symbol
            )
        )

        # call the entry callback
        if self.exit_callback:
            self.exit_callback(self.parameter)

        return self.break_at_exit


# clear all prior breakpoints
gdb.execute("delete")

#
# list of breakpoints
#

# before binder_thread is freed
EnterBp(
    proc_cmd="cve-2019-2215", entry_symbol="binder_free_thread",
    param_list=["thread"], exit_symbol=None, break_at_entry=False,
    entry_callback=set_dump_binder_thread, break_at_exit=False,
    exit_callback=None, set_exit_bp=False
)

# before and after the unlink operation happens
# entry_symbol = remove_wait_queue
# exit_symbol = wait.c:52
EnterBp(
    proc_cmd="cve-2019-2215", entry_symbol="remove_wait_queue",
    param_list=["wq_head", "wq_entry"], exit_symbol="wait.c:52",
    break_at_entry=False, entry_callback=dump_binder_thread,
    break_at_exit=False, exit_callback=dump_binder_thread,
    set_exit_bp=True
)
