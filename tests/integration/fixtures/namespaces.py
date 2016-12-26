import contextlib
import ctypes
import errno
import os
import pyroute2
import pytest
import signal

# All allowed namespace types
NAMESPACE_FLAGS = dict(mnt=0x00020000,
                       uts=0x04000000,
                       ipc=0x08000000,
                       user=0x10000000,
                       pid=0x20000000,
                       net=0x40000000)
STACKSIZE = 1024*1024

libc = ctypes.CDLL('libc.so.6', use_errno=True)


@contextlib.contextmanager
def keep_directory():
    """Restore the current directory on exit."""
    pwd = os.getcwd()
    try:
        yield
    finally:
        os.chdir(pwd)


class Namespace(object):
    """Combine several namespaces into one.

    This gets a list of namespace types to create and combine into one. The
    combined namespace can be used as a context manager to enter all the
    created namespaces and exit them at the end.
    """

    def __init__(self, *namespaces):
        self.namespaces = namespaces
        for ns in namespaces:
            assert ns in NAMESPACE_FLAGS

        # Get a pipe to signal the future child to exit
        self.pipe = os.pipe()

        # First, create a child in the given namespaces
        child = ctypes.CFUNCTYPE(ctypes.c_int)(self.child)
        child_stack = ctypes.create_string_buffer(STACKSIZE)
        child_stack_pointer = ctypes.c_void_p(
            ctypes.cast(child_stack,
                        ctypes.c_void_p).value + STACKSIZE)
        flags = signal.SIGCHLD
        for ns in namespaces:
            flags |= NAMESPACE_FLAGS[ns]
        pid = libc.clone(child, child_stack_pointer, flags)
        if pid == -1:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))

        # If a user namespace, map UID 0 to the current one
        if 'user' in namespaces:
            uid_map = '0 {} 1'.format(os.getuid())
            gid_map = '0 {} 1'.format(os.getgid())
            with open('/proc/{}/uid_map'.format(pid), 'w') as f:
                f.write(uid_map)
            with open('/proc/{}/setgroups'.format(pid), 'w') as f:
                f.write('deny')
            with open('/proc/{}/gid_map'.format(pid), 'w') as f:
                f.write(gid_map)

        # Retrieve a file descriptor to this new namespace
        self.next = [os.open('/proc/{}/ns/{}'.format(pid, x),
                             os.O_RDONLY) for x in namespaces]

        # Keep a file descriptor to our old namespaces
        self.previous = [os.open('/proc/self/ns/{}'.format(x),
                                 os.O_RDONLY) for x in namespaces]

        # Tell the child all is done and let it die
        os.close(self.pipe[0])
        if 'pid' not in namespaces:
            os.close(self.pipe[1])
            self.pipe = None
            os.waitpid(pid, 0)

    def __del__(self):
        for fd in self.next:
            os.close(fd)
        for fd in self.previous:
            os.close(fd)
        if self.pipe is not None:
            os.close(self.pipe[1])

    def child(self):
        """Cloned child.

        Just be here until our parent extract the file descriptor from
        us.

        """
        os.close(self.pipe[1])

        # For a network namespace, enable lo
        if 'net' in self.namespaces:
            ipr = pyroute2.IPRoute()
            lo = ipr.link_lookup(ifname='lo')[0]
            ipr.link('set', index=lo, state='up')
        # For a mount namespace, make it private
        if 'mnt' in self.namespaces:
            libc.mount(b"none", b"/", None,
                       # MS_REC | MS_PRIVATE
                       16384 | (1 << 18),
                       None)

        while True:
            try:
                os.read(self.pipe[0], 1)
            except OSError as e:
                if e.errno in [errno.EAGAIN, errno.EINTR]:
                    continue
            break

        os._exit(0)

    def fd(self, namespace):
        """Return the file descriptor associated to a namespace"""
        assert namespace in self.namespaces
        return self.next[self.namespaces.index(namespace)]

    def __enter__(self):
        with keep_directory():
            for n in self.next:
                if libc.setns(n, 0) == -1:
                    ns = self.namespaces[self.next.index(n)]  # NOQA
                    e = ctypes.get_errno()
                    raise OSError(e, os.strerror(e))

    def __exit__(self, *exc):
        with keep_directory():
            err = None
            for p in reversed(self.previous):
                if libc.setns(p, 0) == -1 and err is None:
                    ns = self.namespaces[self.previous.index(p)]  # NOQA
                    e = ctypes.get_errno()
                    err = OSError(e, os.strerror(e))
            if err:
                raise err

    def __repr__(self):
        return 'Namespace({})'.format(", ".join(self.namespaces))


class NamespaceFactory(object):
    """Dynamically create namespaces as they are created.

    Those namespaces are namespaces for IPC, net, mount and UTS. PID
    is a bit special as we have to keep a process for that. We don't
    do that to ensure that everything is cleaned
    automatically. Therefore, the child process is killed as soon as
    we got a file descriptor to the namespace. We don't use a user
    namespace either because we are unlikely to be able to exit it.

    """

    def __init__(self):
        self.namespaces = {}

    def __call__(self, ns):
        """Return a namespace. Create it if it doesn't exist."""
        if ns in self.namespaces:
            return self.namespaces[ns]
        self.namespaces[ns] = Namespace('ipc', 'net', 'mnt', 'uts')
        return self.namespaces[ns]


@pytest.fixture
def namespaces():
    return NamespaceFactory()
