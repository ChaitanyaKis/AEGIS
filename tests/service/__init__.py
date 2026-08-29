"""Tests for the HTTP surface.

Offline by construction: no credentials, no provider, no network beyond loopback, and no
deployed service. The one test that opens a socket binds ``127.0.0.1`` on an ephemeral port
and talks to itself with the standard library.
"""
