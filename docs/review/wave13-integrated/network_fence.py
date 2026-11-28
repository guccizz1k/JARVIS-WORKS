"""Linux seccomp network syscall fence for an isolated worker only.
Not a filesystem/process sandbox; no inherited sockets, no untrusted production input.
Fail closed on missing libseccomp, unsupported architecture or a failed rule.
"""
import ctypes as C
import ctypes.util
import errno
import os
import platform
import socket
import sys

class FenceError(RuntimeError): pass

NETWORK = ('socket','socketpair','connect','bind','listen','accept','accept4','sendto','sendmsg','sendmmsg','recvfrom','recvmsg','recvmmsg','getsockname','getpeername','setsockopt','getsockopt','shutdown','io_uring_setup','io_uring_enter','io_uring_register')

def install():
    if sys.platform!='linux' or platform.machine() not in ('x86_64','aarch64'):
        raise FenceError('NETWORK_FENCE_PLATFORM')
    lib=C.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.argtypes=[C.c_uint32];lib.seccomp_init.restype=C.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[C.c_char_p];lib.seccomp_syscall_resolve_name.restype=C.c_int
    lib.seccomp_rule_add.argtypes=[C.c_void_p,C.c_uint32,C.c_int,C.c_uint];lib.seccomp_rule_add.restype=C.c_int
    lib.seccomp_load.argtypes=[C.c_void_p];lib.seccomp_load.restype=C.c_int
    lib.seccomp_release.argtypes=[C.c_void_p];lib.seccomp_release.restype=None
    # SCMP_ACT_ALLOW; deny selected syscalls with EPERM. No network namespace claim.
    ctx=lib.seccomp_init(0x7fff0000)
    if not ctx:raise FenceError('NETWORK_FENCE_INIT')
    try:
        for name in NETWORK:
            num=lib.seccomp_syscall_resolve_name(name.encode('ascii'))
            if num<0 or lib.seccomp_rule_add(ctx,0x00050000|errno.EPERM,num,0)!=0:
                raise FenceError('NETWORK_FENCE_RULE')
        if lib.seccomp_load(ctx)!=0:raise FenceError('NETWORK_FENCE_LOAD')
    finally:lib.seccomp_release(ctx)
    for family in (socket.AF_INET,socket.AF_INET6,socket.AF_UNIX):
        try:s=socket.socket(family,socket.SOCK_STREAM)
        except OSError as e:
            if e.errno!=errno.EPERM:raise FenceError('NETWORK_FENCE_SELFTEST') from None
        else:
            s.close();raise FenceError('NETWORK_FENCE_SELFTEST')
    return 'SOCKET_SYSCALL_DENIAL_ONLY'
