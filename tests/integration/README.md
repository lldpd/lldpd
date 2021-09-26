lldpd integration tests
=======================

To run those tests, you need Python 3.

    $ virtualenv -p /usr/bin/python3 venv
    $ . venv/bin/activate
    $ pip install -r requirements.txt

The tests rely on namespace support. Therefore, they only work on
Linux. At least a 3.11 kernel is needed. While it would have been
convenient to rely on a user namespace to avoid to run tests as root,
there are restrictions that makes that difficult, notably we can only
map one user to root and we have to map the current user and the
_lldpd user.

Then, tests can be run with:

    $ sudo $(which pytest) -vv -n 10 --boxed

Add an additional `-v` to get even more traces.
