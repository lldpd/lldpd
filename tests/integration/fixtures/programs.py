import pytest
import glob
import os
import pwd
import grp
import re
import signal
import subprocess
import multiprocessing
import uuid
import time
import platform
import ctypes
from collections import namedtuple

from .namespaces import mount_proc, mount_tmpfs

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def mount_bind(source, target):
    ret = libc.mount(
        source.encode("ascii"), target.encode("ascii"), None, 4096, None  # MS_BIND
    )
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def most_recent(*args):
    """Return the most recent files matching one of the provided glob
    expression."""
    candidates = [l for location in args for l in glob.glob(location)]
    candidates.sort(key=lambda x: os.stat(x).st_mtime)
    assert len(candidates) > 0
    return candidates[0]


libtool_location = most_recent("../../libtool", "../../*/libtool")
lldpcli_location = most_recent("../../src/client/lldpcli", "../../*/src/client/lldpcli")
lldpd_location = most_recent("../../src/daemon/lldpd", "../../*/src/daemon/lldpd")


def _replace_file(tmpdir, target, content):
    tmpname = str(uuid.uuid1())
    with tmpdir.join(tmpname).open("w") as tmp:
        tmp.write(content)
        mount_bind(str(tmpdir.join(tmpname)), target)


@pytest.fixture
def replace_file(tmpdir):
    """Replace a file by another content by bind-mounting on it."""
    return lambda target, content: _replace_file(tmpdir, target, content)


def format_process_output(program, args, result):
    """Return a string representing the result of a process."""
    return "\n".join(
        [
            "P: {} {}".format(program, " ".join(args)),
            "C: {}".format(os.getcwd()),
            "\n".join(
                [
                    "O: {}".format(l)
                    for l in result.stdout.decode("ascii", "ignore").strip().split("\n")
                ]
            ),
            "\n".join(
                [
                    "E: {}".format(l)
                    for l in result.stderr.decode("ascii", "ignore").strip().split("\n")
                ]
            ),
            "S: {}".format(result.returncode),
            "",
        ]
    )


class LldpdFactory(object):
    """Factory for lldpd. When invoked, lldpd will configure the current
    namespace to be in a reproducible environment and spawn itself in
    the background. On termination, output will be logged to temporary
    file.
    """

    def __init__(self, tmpdir, config):
        """Create a new wrapped program."""
        tmpdir.join("lldpd-outputs").ensure(dir=True)
        self.tmpdir = tmpdir
        self.config = config
        self.pids = []
        self.threads = []
        self.counter = 0

    def __call__(self, *args, sleep=3, silent=False):
        self.counter += 1
        self.setup_namespace("ns-{}".format(self.counter))
        args = (
            self.config.option.verbose > 2 and "-dddd" or "-dd",
            "-L",
            lldpcli_location,
            "-u",
            str(self.tmpdir.join("ns", "lldpd.socket")),
        ) + args
        p = subprocess.Popen(
            (libtool_location, "execute", lldpd_location) + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.pids.append(p.pid)
        t = multiprocessing.Process(target=self.run, args=(p, args, silent))
        self.threads.append(t)
        t.start()
        time.sleep(sleep)
        return t

    def run(self, p, args, silent):
        stdout, stderr = p.communicate()
        self.pids.remove(p.pid)
        if not silent:
            o = format_process_output(
                "lldpd",
                args,
                namedtuple("ProcessResult", ["returncode", "stdout", "stderr"])(
                    p.returncode, stdout, stderr
                ),
            )
            self.tmpdir.join("lldpd-outputs", "{}-{}".format(os.getpid(), p.pid)).write(
                o
            )

    def killall(self):
        for p in self.pids[:]:
            try:
                os.kill(p, signal.SIGTERM)
            except ProcessLookupError:
                continue
        for t in self.threads:
            if t.is_alive():
                t.join(1)
        for p in self.pids[:]:
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                continue
        for t in self.threads:
            if t.is_alive():
                t.join(1)

    def setup_namespace(self, name):
        # Setup privsep. While not enforced, we assume we are running in a
        # throwaway mount namespace.
        tmpdir = self.tmpdir
        if self.config.lldpd.privsep.enabled:
            # Chroot
            chroot = self.config.lldpd.privsep.chroot
            parent = os.path.abspath(os.path.join(chroot, os.pardir))
            assert os.path.isdir(parent)
            mount_tmpfs(parent)
            # User/group
            user = self.config.lldpd.privsep.user
            group = self.config.lldpd.privsep.group
            try:
                pwd.getpwnam(user)
                grp.getgrnam(group)
            except KeyError:
                passwd = ""
                for l in open("/etc/passwd", "r").readlines():
                    if not l.startswith("{}:".format(user)):
                        passwd += l
                passwd += "{}:x:39861:39861::{}:/bin/false\n".format(user, chroot)
                fgroup = ""
                for l in open("/etc/group", "r").readlines():
                    if not l.startswith("{}:".format(group)):
                        fgroup += l
                fgroup += "{}:x:39861:\n".format(group)
                _replace_file(tmpdir, "/etc/passwd", passwd)
                _replace_file(tmpdir, "/etc/group", fgroup)

        # We also need a proper /etc/os-release
        _replace_file(
            tmpdir,
            "/etc/os-release",
            """PRETTY_NAME="Spectacular GNU/Linux 2016"
NAME="Spectacular GNU/Linux"
ID=spectacular
HOME_URL="https://www.example.com/spectacular"
SUPPORT_URL="https://www.example.com/spectacular/support"
BUG_REPORT_URL="https://www.example.com/spectacular/bugs"
""",
        )

        # We also need a proper name
        subprocess.check_call(["hostname", name])

        # And we need to ensure name resolution is sane
        _replace_file(
            tmpdir,
            "/etc/hosts",
            """
127.0.0.1 localhost.localdomain localhost
127.0.1.1 {name}.example.com {name}
::1       ip6-localhost ip6-loopback
""".format(
                name=name
            ),
        )
        _replace_file(
            tmpdir,
            "/etc/nsswitch.conf",
            """
passwd: files
group: files
shadow: files
hosts: files
networks: files
protocols: files
services: files
""",
        )

        # Remove any config
        path = os.path.join(self.config.lldpd.confdir, "lldpd.conf")
        if os.path.isfile(path):
            _replace_file(tmpdir, path, "")
        path = os.path.join(self.config.lldpd.confdir, "lldpd.d")
        if os.path.isdir(path):
            mount_tmpfs(path)


@pytest.fixture()
def lldpd(request, tmpdir):
    """Execute ``lldpd``."""
    p = LldpdFactory(tmpdir, request.config)
    request.addfinalizer(p.killall)
    return p


@pytest.fixture()
def lldpd1(lldpd, links, namespaces):
    """Shortcut for a first receive-only lldpd daemon."""
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-r")


@pytest.fixture()
def lldpcli(request, tmpdir):
    """Execute ``lldpcli``."""
    socketdir = tmpdir.join("ns", "lldpd.socket")
    count = [0]

    def run(*args):
        cargs = ("-u", str(socketdir)) + args
        p = subprocess.Popen(
            (libtool_location, "execute", lldpcli_location) + cargs,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate(timeout=30)
        result = namedtuple("ProcessResult", ["returncode", "stdout", "stderr"])(
            p.returncode, stdout, stderr
        )
        request.node.add_report_section(
            "run",
            "lldpcli output {}".format(count[0]),
            format_process_output("lldpcli", cargs, result),
        )
        count[0] += 1
        # When keyvalue is requested, return a formatted result
        if args[:2] == ("-f", "keyvalue"):
            assert result.returncode == 0
            out = {}
            for k, v in [
                l.split("=", 2)
                for l in result.stdout.decode("ascii").split("\n")
                if "=" in l
            ]:
                if k in out:
                    out[k] += [v]
                else:
                    out[k] = [v]
            for k in out:
                if len(out[k]) == 1:
                    out[k] = out[k][0]
            return out
        # Otherwise, return the named tuple
        return result

    return run


@pytest.fixture()
def snmpd(request, tmpdir):
    """Execute ``snmpd``."""
    count = [0]

    def run(*args):
        conffile = tmpdir.join("ns", "snmpd.conf")
        pidfile = tmpdir.join("ns", "snmpd.pid")
        with conffile.open("w") as f:
            f.write(
                """
rocommunity public
rwcommunity private
master agentx
trap2sink 127.0.0.1
"""
            )
        sargs = (
            "-I",
            "snmp_mib,sysORTable"
            ",usmConf,usmStats,usmUser"
            ",vacm_conf,vacm_context,vacm_vars",
            "-Ln",
            "-p",
            str(pidfile),
            "-C",
            "-c",
            str(conffile),
        )
        try:
            p = subprocess.Popen(
                ("snmpd",) + sargs + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                pytest.skip("snmpd not present")
                return
            raise e
        stdout, stderr = p.communicate(timeout=5)
        result = namedtuple("ProcessResult", ["returncode", "stdout", "stderr"])(
            p.returncode, stdout, stderr
        )
        request.node.add_report_section(
            "run",
            "snmpd output {}".format(count[0]),
            format_process_output("snmpd", sargs, result),
        )
        count[0] += 1
        time.sleep(1)

        def kill():
            try:
                with pidfile.open("r") as p:
                    os.kill(int(p.read()))
            except:
                pass

        request.addfinalizer(kill)

    return run


@pytest.fixture()
def snmpwalk():
    def run(*args):
        try:
            p = subprocess.Popen(
                (
                    "env",
                    "MIBDIRS=",
                    "snmpwalk",
                    "-v2c",
                    "-c",
                    "private",
                    "-Ob",
                    "-Oe",
                    "-On",
                    "localhost",
                )
                + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                pytest.skip("snmpwalk not present")
                return
            raise e
        stdout, stderr = p.communicate(timeout=30)
        result = namedtuple("ProcessResult", ["returncode", "stdout", "stderr"])(
            p.returncode, stdout, stderr
        )
        # When keyvalue is requested, return a formatted result
        assert result.returncode == 0
        out = {}
        for k, v in [
            l.split(" = ", 2)
            for l in result.stdout.decode("ascii").split("\n")
            if " = " in l
        ]:
            out[k] = v
        return out

    return run


def pytest_runtest_makereport(item, call):
    """Collect outputs written to tmpdir and put them in report."""
    # Only do that after tests are run, but not on teardown (too late)
    if call.when != "call":
        return
    # We can't wait for teardown, kill any running lldpd daemon right
    # now. Otherwise, we won't get any output.
    if "lldpd" in item.fixturenames and "lldpd" in item.funcargs:
        lldpd = item.funcargs["lldpd"]
        lldpd.killall()
    if "tmpdir" in item.fixturenames and "tmpdir" in item.funcargs:
        tmpdir = item.funcargs["tmpdir"]
        if tmpdir.join("lldpd-outputs").check(dir=1):
            for path in tmpdir.join("lldpd-outputs").visit():
                item.add_report_section(
                    call.when, "lldpd {}".format(path.basename), path.read()
                )


def pytest_configure(config):
    """Put lldpd/lldpcli configuration into the config object."""
    output = subprocess.check_output([lldpcli_location, "-vv"])
    output = output.decode("ascii")
    config.lldpcli = namedtuple("lldpcli", ["version", "outputs"])(
        re.search(r"^lldpcli (.*)$", output, re.MULTILINE).group(1),
        re.search(r"^Additional output formats:\s+(.*)$", output, re.MULTILINE)
        .group(1)
        .split(", "),
    )
    output = subprocess.check_output([lldpd_location, "-vv"])
    output = output.decode("ascii")
    if {"enabled": True, "disabled": False}[
        re.search(r"^Privilege separation:\s+(.*)$", output, re.MULTILINE).group(1)
    ]:
        privsep = namedtuple("privsep", ["user", "group", "chroot", "enabled"])(
            re.search(
                r"^Privilege separation user:\s+(.*)$", output, re.MULTILINE
            ).group(1),
            re.search(
                r"^Privilege separation group:\s+(.*)$", output, re.MULTILINE
            ).group(1),
            re.search(
                r"^Privilege separation chroot:\s(.*)$", output, re.MULTILINE
            ).group(1),
            True,
        )
    else:
        privsep = namedtuple("privsep", ["enabled"])(False)
    config.lldpd = namedtuple(
        "lldpd", ["features", "protocols", "confdir", "snmp", "privsep", "version"]
    )(
        re.search(r"^Additional LLDP features:\s+(.*)$", output, re.MULTILINE)
        .group(1)
        .split(", "),
        re.search(r"^Additional protocols:\s+(.*)$", output, re.MULTILINE)
        .group(1)
        .split(", "),
        re.search(r"^Configuration directory:\s+(.*)$", output, re.MULTILINE).group(1),
        {"yes": True, "no": False}[
            re.search(r"^SNMP support:\s+(.*)$", output, re.MULTILINE).group(1)
        ],
        privsep,
        re.search(r"^lldpd (.*)$", output, re.MULTILINE).group(1),
    )

    # Also retrieve some kernel capabilities
    features = []
    for feature in ["rtnl-link-team"]:
        ret = subprocess.call(["/sbin/modprobe", "--quiet", "--dry-run", feature])
        if ret == 0:
            features.append(feature)
    config.kernel = namedtuple("kernel", ["features", "version"])(
        features, os.uname().release
    )


def pytest_report_header(config):
    """Report lldpd/lldpcli version and configuration."""
    print(
        "lldpd: {} {}".format(
            config.lldpd.version,
            ", ".join(config.lldpd.protocols + config.lldpd.features),
        )
    )
    print(
        "lldpcli: {} {}".format(
            config.lldpcli.version, ", ".join(config.lldpcli.outputs)
        )
    )
    print(
        "kernel: {} {}".format(config.kernel.version, ", ".join(config.kernel.features))
    )
    print(
        "{}: {} {} {}".format(
            platform.system().lower(),
            platform.release(),
            platform.version(),
            platform.machine(),
        )
    )
