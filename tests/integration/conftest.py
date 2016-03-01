import pytest
from fixtures.programs import *
from fixtures.namespaces import *
from fixtures.network import *


@pytest.yield_fixture(autouse=True, scope='session')
def root():
    """Ensure we are somewhat root."""
    # We could do a user namespace but there are too many
    # restrictions: we cannot do arbitrary user mapping and therefore,
    # this doesn't play well with privilege separation and the use of
    # _lldpd. Just do a plain namespace.
    with Namespace('pid', 'net', 'mnt', 'ipc', 'uts'):
        yield
