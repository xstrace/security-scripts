#coding:utf-8

import os
import sys
import traceback
import re 
import shutil
import ctypes


def getProcessInfo(pid):
    proc_dir_base = '/proc/%d' % pid 

    if not os.path.exists(proc_dir_base):
        raise Exception("pid_not_exists: %s" % proc_dir_base)

    proc_comm = proc_dir_base + '/comm'
    proc_exe = proc_dir_base + '/exe'
    proc_cmdline = proc_dir_base + '/cmdline'
    proc_maps = proc_dir_base + '/maps'

    proc_info = {
        'pid': pid,
        'comm': '',
        'exe': '',
        'cmdline': '',
        'maps': [],
        'maps_raw': ''
    }

    with open(proc_comm, 'r') as f:
        proc_info['comm'] = f.read(32).rstrip()
    
    try:
        proc_info['exe'] = os.readlink(proc_exe)
    except:
        traceback.print_exc()

    with open(proc_cmdline, 'rb') as f:
        cmdline_raw = f.read(4096).rstrip('\x00')    
        proc_info['cmdline'] = ' '.join(cmdline_raw.split('\x00'))
    
    # parse maps 

    with open(proc_maps, 'r') as f:
        proc_info['maps_raw'] = f.read()
    
    if len(proc_info['maps_raw']) == 0:
        raise Exception('proc_maps_len_0')

    for line in proc_info['maps_raw'].splitlines():
        line = line.rstrip()
        searcher = re.search(
            r'^([0-9a-f]+)\-([0-9a-f]+)\s+([\w\-]+)\s+([0-9a-f]+)\s+([0-9a-f:]+)\s+(\d+)\s*(.*)$'
            , line 
            )
        if searcher is None:
            print('[~] parse_maps_error %s' % line)
            continue 
        proc_info['maps'].append(
            {
                'start': searcher.group(1),
                'end': searcher.group(2),
                'flag': searcher.group(3),
                'offset': searcher.group(4),
                'device': searcher.group(5),
                'inode': searcher.group(6),
                'desc': searcher.group(7)
            }
        )



    # print('proc_info', proc_info)
    return proc_info

def ptrace(pid, action):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    c_ptrace = libc.ptrace
    c_pid_t = ctypes.c_int32  # This assumes pid_t is int32_t
    c_ptrace.argtypes = [ctypes.c_int, c_pid_t, ctypes.c_void_p, ctypes.c_void_p]
    c_ptrace.restype = ctypes.c_long

    if action == 'attach':
        op = 16 
    else:
        op = 17

    c_pid = c_pid_t(pid)
    null = ctypes.c_void_p()
    err = c_ptrace(op, c_pid, null, null)
    if err != 0:
        print '[~] ptrace_error %d' % pid

def dumpProcess(pid):
    process_info = getProcessInfo(pid)

    # mk result dir 
    result_dir = './process_dump_%s_%d' % (process_info['comm'], pid)
    if os.path.exists(result_dir):
        shutil.rmtree(result_dir)
    os.mkdir(result_dir)

    # basic info 
    with open(result_dir + '/process_snapshot_info.txt', 'w') as f:
        f.write('%s: %d\n\n' % ('pid', process_info['pid']))
        f.write('%s: %s\n\n' % ('comm', process_info['comm']))
        f.write('%s: %s\n\n' % ('exe', process_info['exe']))
        f.write('%s: %s\n\n' % ('cmdline', process_info['cmdline']))
        f.write('%s: \n%s\n\n' % ('maps', process_info['maps_raw']))

    # from mem 
    ptrace(pid, 'attach')
    for mapinfo in process_info['maps']:
        try:
            if mapinfo['desc'].startswith('/') and os.path.exists(mapinfo['desc']):
                continue 
            if mapinfo['desc'] in ('[vsyscall]',):
                continue

            start_address = int(mapinfo['start'], 16)
            end_address = int(mapinfo['end'], 16)
            buffer_size = end_address - start_address

            fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
            os.lseek(fd, start_address, 0)
            buffer = os.read(fd, buffer_size)
     
            result_file_path = result_dir + '/%s-%s.dmp' % (mapinfo['start'], mapinfo['end'])
            with open(result_file_path, 'wb') as f:
                f.write(buffer)

            # print buffer[0: 100]
        except Exception as e:
            print '[~] error_when_handle %s %s' % (mapinfo, str(e))
            # traceback.print_exc()
    
    ptrace(pid, 'detach')

if __name__ == "__main__":
    pid_str = sys.argv[1]
    pid = int(pid_str)
    dumpProcess(pid)
