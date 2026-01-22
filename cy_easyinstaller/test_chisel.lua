-- Chisel description
description = "Monitor file creations, deletions, and exec calls."
short_description = "Track file creation, deletion, and exec."
category = "Application monitoring"

-- Chisel argument list
args = {}

-- Event types to monitor
-- For file creation: evt.type=open, evt.type=creat
-- For file deletion: evt.type=unlink, evt.type=unlinkat
-- For exec calls: evt.type=execve
function on_init()
    -- Request the fields we will be using in the chisel
    _process_name = chisel.request_field("proc.name")
    _parent_process_name = chisel.request_field("proc.pname")
    _pid = chisel.request_field("proc.pid") 
    _arg_name = chisel.request_field("evt.arg.name")
    _arg_path = chisel.request_field("evt.arg.path")

    chisel.set_filter("evt.type in (unlink,unlinkat,execve) or (evt.type in (open,openat) and (evt.arg.flags contains O_CREAT))")
    return true
end

-- Define the event handler
function on_event()
    local name = evt.field(_process_name)
    local parent_name = evt.field(_parent_process_name)
    local pid = evt.field(_pid)
    local arg_name = evt.field(_arg_name)
    local arg_path = evt.field(_arg_path)
    local evt_type = evt.get_type()

    -- Handle file creations (open or creat syscalls)
    if evt_type == "open" or evt_type == "openat" then
        if arg_name ~= nil then
            print(string.format("create: %s - %d - %s", name, pid, arg_name))
        else
            print(string.format("Unexpected data in file deletion (%s) event. Aborting...", evt_type))
        end
        return true
    end

    -- Handle file deletions (unlink or unlinkat syscalls)
    if(evt_type == "unlink" or evt_type == "unlinkat") then 
        full_path = arg_path
        if(evt_type == "unlinkat") then
            full_path = arg_name
        end 

        if full_path ~= nil then
            print(string.format("delete: %s - %d - %s", name, pid, full_path))
        else
            print(string.format("Unexpected data in file deletion (%s) event (arg_name: '%s'  arg_path: '%s'). Aborting...", evt_type, arg_name, arg_path))
        end
        return true
    end

    -- Handle exec calls (execve syscall)
    if evt_type == "execve" then
        if parent_name ~= nil then
            print(string.format("exec: %s - %s", parent_name, name))
        else
            print(string.format("Unexpected data in file deletion (%s) event. Aborting...", evt_type))
        end
    end

    return true
end