import ctypes, os, sys, urllib2
libc = ctypes.CDLL(None)

def exec_memfd(data, args):
    fd = ctypes.CDLL(None).syscall(319, "test", 1)
    url = args[0]
    os.write(fd, data)
    pid = os.getpid()
    path = "/proc/{}/fd/{}".format(pid, fd)
    argv = args
    env = {}
    os.execve(path, argv, env)

def exec_file(args):
    fc = open(args[0], 'rb').read()
    exec_memfd(fc, args[:])

exec_file(sys.argv[1:])
