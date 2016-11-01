# Unittests for util module.
# coding: utf-8
# Copyright (C) 2009  Manuel Hermann <manuel-hermann@gmx.net>
#
# This file is part of tinydav.
#
# tinydav is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Unittests for util module."""

from __future__ import with_statement, unicode_literals
import sys
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import unittest

from tinydav import HTTPClient, HTTPError
from tinydav import util

from Mock import injected
import Mock
import pytest

PYTHON2 = ((2, 5) <= sys.version_info <= (3, 0))

if PYTHON2:
    newline_if_py3 = ''
else:
    newline_if_py3 = '\n'

MULTI = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="b"

bar
--foobar--"""


MULTI_ISO = """\
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="b"

=E4=F6=FC=DF
--foobar--"""


MIME_ISO_EXPLICIT = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="b"

=E4=F6=FC=DF
--foobar--"""


MIME_FILE = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4={}
--foobar--"""


MIME_FILE_EXPLICIT = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4={}
--foobar--"""


MIME_FILE_NAME = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"; filename="test.txt"

VGhpcyBpcyBhIHRlc3QgZmlsZS4={}
--foobar--"""


MIME_FILES = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: multipart/mixed; boundary="foobar-mixed"
MIME-Version: 1.0

--foobar-mixed
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: file; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4={0}
--foobar-mixed
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: file; name="c"; filename="test2.txt"

VGhpcyBpcyBhbm90aGVyIHRlc3QgZmlsZS4={0}
--foobar-mixed--{0}
--foobar--"""


class UtilTestCase(unittest.TestCase):
    """Test util module."""

    def test_fake_http_request(self):
        """Test util.FakeHTTPReqest."""
        client = HTTPClient("localhost")
        headers = dict(a="1", b="2")
        fake = util.FakeHTTPRequest(client, "/foo/bar", headers)
        assert fake.get_full_url() == "http://localhost:80/foo/bar"
        assert fake.get_host() == "localhost"
        assert not fake.is_unverifiable()
        assert fake.get_origin_req_host() == "localhost"
        assert fake.get_type() == "http"
        assert fake.has_header("a")
        assert not fake.has_header("foobar")
        fake.add_unredirected_header("foobar", "baz")
        assert fake.has_header("foobar")

    def test_make_absolute(self):
        """Test util.make_absolute function."""
        mockclient = Mock.Omnivore()
        mockclient.protocol = "http"
        mockclient.host = "localhost"
        mockclient.port = 80
        expect = "http://localhost:80/foo/bar"
        assert util.make_absolute(mockclient, "/foo/bar") == expect

    def test_extract_namespace(self):
        """Test util.extrace_namespace."""
        assert util.extract_namespace("{foo}bar") == "foo"
        assert util.extract_namespace("bar") == None

    def test_get_depth(self):
        """Test util.get_depth."""
        # test unrestricted
        assert util.get_depth("0") == "0"
        assert util.get_depth(0) == "0"
        assert util.get_depth("1") == "1"
        assert util.get_depth(1) == "1"
        assert util.get_depth("InFiNiTy") == "infinity"
        with pytest.raises(ValueError):
            util.get_depth("illegal")
        # test restricted
        restricted = ("0", "infinity")
        assert util.get_depth("0", restricted) == "0"
        assert util.get_depth(0, restricted) == "0"
        with pytest.raises(ValueError):
            util.get_depth("1", restricted)
        with pytest.raises(ValueError):
            util.get_depth(1, restricted)
        assert util.get_depth("InFiNiTy", restricted) == "infinity"

    def test_get_cookie_response(self):
        """Test util.get_cookie_response."""
        response = Mock.Omnivore()
        response.response = Mock.Omnivore()
        response.response.msg = "The message"
        assert util.get_cookie_response(response) == response.response
        # must extract response object from HTTPError
        error = HTTPError(response)
        assert util.get_cookie_response(error) == response.response

    def test_parse_authenticate(self):
        """Test util.parse_authenticate."""
        # basic auth
        basic = 'Basic realm="restricted"'
        authdata = util.parse_authenticate(basic)
        assert authdata.get("schema") == "Basic"
        assert authdata.get("realm") == "restricted"
        assert authdata.get("domain") == None
        assert authdata.get("nonce") == None
        assert authdata.get("opaque") == None
        assert authdata.get("stale") == None
        assert authdata.get("algorithm") == None
        # digest auth
        digest = 'Digest realm="restricted" domain="foo.de" nonce="abcd1234"'\
                 'opaque="qwer4321" stale=false algorithm="MD5"'
        authdata = util.parse_authenticate(digest)
        assert authdata.get("schema") == "Digest"
        assert authdata.get("realm") == "restricted"
        assert authdata.get("domain") == "foo.de"
        assert authdata.get("nonce") == "abcd1234"
        assert authdata.get("opaque") == "qwer4321"
        assert authdata.get("stale") == "false"
        assert authdata.get("algorithm") == "MD5"
        # digest auth missing something
        digest = 'Digest realm="restricted" domain="foo.de" nonce="abcd1234"'\
                 'opaque="qwer4321" algorithm="MD5"'
        authdata = util.parse_authenticate(digest)
        assert authdata.get("schema") == "Digest"
        assert authdata.get("realm") == "restricted"
        assert authdata.get("domain") == "foo.de"
        assert authdata.get("nonce") == "abcd1234"
        assert authdata.get("opaque") == "qwer4321"
        assert authdata.get("stale") is None
        assert authdata.get("algorithm") == "MD5"
        # broken authenticate header
        authdata = util.parse_authenticate("Nothing")
        assert authdata == dict()

    def test_make_multipart(self):
        """Test util.make_multipart."""
        # form-data
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b="bar")
            (headers, multi) = util.make_multipart(content)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MULTI

    def test_make_multipart_iso(self):
        # form-data with iso-8859-1
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b="äöüß")
            (headers, multi) = util.make_multipart(content, "iso-8859-1")
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MULTI_ISO

    def test_make_multipart_iso_explicit(self):
        # form-data with explicit iso-8859-1
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=("äöüß", "iso-8859-1"))
            (headers, multi) = util.make_multipart(content)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MIME_ISO_EXPLICIT

    def test_make_multipart_file(self):
        # post one file
        sio = StringIO("This is a test file.")
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio)
            (headers, multi) = util.make_multipart(content)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MIME_FILE.format(newline_if_py3)

    def test_make_multipart_file_name(self):
        # post one file with filename
        sio = StringIO("This is a test file.")
        sio.name = "test.txt"
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio)
            (headers, multi) = util.make_multipart(
                content, with_filenames=True)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MIME_FILE_NAME.format(newline_if_py3)

    def test_make_multipart_file_explicit(self):
        # post one file with explicit content-type
        sio = StringIO("This is a test file.")
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=(sio, "text/plain"))
            (headers, multi) = util.make_multipart(content)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MIME_FILE_EXPLICIT.format(newline_if_py3)

    def test_make_multipart_files(self):
        # post two files, one with filename
        sio = StringIO("This is a test file.")
        sio2 = StringIO("This is another test file.")
        sio2.name = "test2.txt"
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio, c=sio2)
            (headers, multi) = util.make_multipart(
                content, with_filenames=True)
            assert headers["Content-Type"] == \
                'multipart/form-data; boundary="foobar"'
            assert multi.strip() == MIME_FILES.format(newline_if_py3)
