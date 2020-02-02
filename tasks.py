from invoke import task

import os
import sys
import glob
import hashlib
import tempfile
import shutil

os.environ["PATH"] = os.path.expanduser('~/.virtualenvs/hyde/bin') \
    + os.pathsep + os.environ["PATH"]


def confirm(question, default=False):
    if default:
        suffix = "Y/n"
    else:
        suffix = "y/N"
    while True:
        response = input("{0} [{1}] ".format(question, suffix))
        response = response.lower().strip()  # Normalize
        # Default
        if not response:
            return default
        if response in ["y", "yes"]:
            return True
        if response in ["n", "no"]:
            return False
        err = "I didn't understand you. Please specify '(y)es' or '(n)o'."
        print(err, file=sys.stderr)


@task
def gen(c):
    """Generate dev content"""
    c.run('hyde -x gen')


@task(post=[gen])
def regen(c):
    """Regenerate dev content"""
    c.run('rm -rf deploy')


@task
def serve(c):
    """Serve dev content"""
    c.run('hyde -x serve -a 0.0.0.0')


@task
def build(c):
    """Build production content"""
    # Generate the website from scratch
    c.run("rm -rf deploy")
    conf = "site-production.yaml"
    c.run('hyde gen -c %s' % conf)

    # Compute hash for media files
    with c.cd("deploy"):
        for p in ['media/js/*.js',
                  'media/css/*.css']:
            files = glob.glob("%s/%s" % (c.cwd, p))
            for f in files:
                # Compute hash
                md5 = hashlib.md5()
                md5.update(open(f, 'rb').read())
                md5 = md5.hexdigest()[:8]
                f = f[len(c.cwd)+1:]
                print("[+] MD5 hash for %s is %s" % (f, md5))
                # New name
                root, ext = os.path.splitext(f)
                newname = "%s.%s%s" % (root, md5, ext)
                # Symlink
                c.run("cp %s %s" % (f, newname))
                # Fix HTML
                c.run(r"find . -name '*.html' -type f -print0 | xargs -r0 sed -i "
                      '"'
                      r"s@\([\"']\)\([^\"']*\)%s\1@\1\2%s\1@g"
                      '"' % (f, newname))

    lldpdir = os.getcwd()
    tempdir = tempfile.mkdtemp()
    try:
        with c.cd(tempdir):
            c.run("git clone %s -b gh-pages ." % lldpdir)
            c.run("rsync -ac --exclude=.git %s/deploy/ ." % lldpdir)
            c.run("git add .")
            c.run("git diff --stat HEAD || true", pty=True)
            if confirm("More diff?", default=True):
                c.run("git diff --word-diff HEAD || true", pty=True)
            if confirm("Keep?", default=True):
                c.run('git commit -a -m "Update generated copy of website"')
                c.run('git push origin')
    finally:
        shutil.rmtree(tempdir)
