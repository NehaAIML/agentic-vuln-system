"""
This module imports `jinja2` but never actually uses it anywhere in the
codebase (simulating a transitive dependency that's installed but dead code).
A naive scanner would flag jinja2's CVE here; reachability analysis should
filter it out.
"""

import jinja2  # noqa: F401


def unrelated_function(x, y):
    return x + y
