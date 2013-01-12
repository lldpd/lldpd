from fabric.api import *

import os
import glob
import hashlib
import tempfile
import shutil

os.umask(0022)
env.shell = "/bin/sh -c"
env.command_prefixes = [ 'export PATH=$HOME/.virtualenvs/hyde/bin:$PATH',
                         'export VIRTUAL_ENV=$HOME/.virtualenvs/hyde' ]

def _hyde(args):
    return local('python ../hyde/h %s' % args)

def gen():
    """Generate dev content"""
    _hyde('gen')

def serve():
    """Serve dev content"""
    _hyde('serve -a 0.0.0.0')

def build():
    """Build production content"""
    # Generate the website from scratch
    local("rm -rf deploy")
    gen()

    # Compute hash for media files
    with lcd("deploy"):
        for p in [ 'media/js/*.js',
                   'media/css/*.css' ]:
            files = glob.glob("%s/%s" % (env.lcwd, p))
            for f in files:
                # Compute hash
                md5 = hashlib.md5()
                md5.update(file(f).read())
                md5 = md5.hexdigest()[:8]
                f = f[len(env.lcwd)+1:]
                print "[+] MD5 hash for %s is %s" % (f, md5)
                # New name
                root, ext = os.path.splitext(f)
                newname = "%s.%s%s" % (root, md5, ext)
                # Symlink
                local("ln -s %s %s" % (os.path.basename(f), newname))
                # Fix HTML
                local(r"find . -name '*.html' -type f -print0 | xargs -r0 sed -i "
                      '"'
                      r"s@\([\"']\)%s\1@\1%s\1@g"
                      '"' % (f, newname))

    lldpdir = os.getcwd()
    tempdir = tempfile.mkdtemp()
    try:
        with lcd(tempdir):
            local("git clone %s -b gh-pages ." % lldpdir)
            local("rsync --delete -a --exclude=.git %s/deploy/ ." % lldpdir)
            local("git add .")
            local("git diff --stat HEAD")
            answer = prompt("More diff?", default="yes")
            if answer.lower().startswith("y"):
                local("git diff --word-diff HEAD")
            answer = prompt("Keep?", default="yes")
            if answer.lower().startswith("y"):
                local('git commit -a -m "Update generated copy of website"')
                local('git push origin')
    finally:
        shutil.rmtree(tempdir)

def push():
    """Push production content to remote locations"""
    local("git push origin gh-pages")
    local("git push origin website")
