#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2010 psy <root@lordepsylon.net>

xsser is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 3 of the License.

xsser is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with xsser; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import os, urllib, mimetools, pycurl


try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


class Curl:
    """
    Class to control curl on behalf of the application.
    """
    agent = 'Googlebot/2.1 (+http://www.google.com/bot.html'
    cookie = None
    referer = None
    headers = None
    atype = None
    acred = None
    proxy = None
    delay = 8

    def __init__(self, base_url="", fakeheaders=[ 'Accept: image/gif, image/x-bitmap, image/jpeg, image/pjpeg', 'Connection: Keep-Alive', 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' ]):
        self.handle = pycurl.Curl()
        self._closed = False
        self.set_url(base_url)
        self.verbosity = 0
        self.signals = 1
        self.payload = ""
        self.header = StringIO()
        self.fakeheaders = fakeheaders
        self.headers = fakeheaders
        self.set_option(pycurl.SSL_VERIFYHOST, 1)
        self.set_option(pycurl.SSL_VERIFYPEER, 0)
        self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv3)
        self.set_option(pycurl.FOLLOWLOCATION, 1)
        self.set_option(pycurl.MAXREDIRS, 5)
        self.set_option(pycurl.COOKIEFILE, "/dev/null")
        self.set_timeout(30)
        self.set_option(pycurl.NETRC, 1)
        self.set_nosignals(1)

        def payload_callback(x):
            self.payload += x
        self.set_option(pycurl.WRITEFUNCTION, payload_callback)
        def header_callback(x):
            self.header.write(x)
        self.set_option(pycurl.HEADERFUNCTION, header_callback)

    def set_url(self, url):
        """
        Set the base url.
        """
        self.base_url = url
        self.set_option(pycurl.URL, self.base_url)

    def set_cookie(self, cookie):
        """
        Set the app cookie.
        """
        self.cookie = cookie
        self.set_option(pycurl.COOKIEFILE, self.cookie)

    def set_agent(self, agent):
        """
        Set the user agent.
        """
        self.agent = agent
        self.set_option(pycurl.USERAGENT, self.agent)

    def set_referer(self, referer):
        """
        Set the referer.
        """
        self.referer = referer
        self.set_option(pycurl.REFERER, self.referer)

    def set_proxy(self, proxy):
        """
        Set the proxy to use.
        """
        self.proxy = proxy
        self.set_option(pycurl.PROXY, self.proxy)

    def set_option(self, *args):
        """
        Set the given option.
        """
        apply(self.handle.setopt, args)

    def set_verbosity(self, level):
        """
        Set the verbosity level.
        """
        self.set_option(pycurl.VERBOSE, level)

    def set_nosignals(self, signals="1"):
        """
        Disable signals.

        curl will be using other means besides signals to timeout
        """
        self.signals = signals
        self.set_option(pycurl.NOSIGNAL, self.signals)

    def set_timeout(self, timeout):
        """
        Set timeout for requests.
        """
        self.set_option(pycurl.CONNECTTIMEOUT,timeout)
        self.set_option(pycurl.TIMEOUT, timeout)

    def __request(self, relative_url=None):
        """
        Perform a request and returns the payload.
        """
        if self.fakeheaders:
            self.set_option(pycurl.HTTPHEADER, self.fakeheaders)
        if self.agent:
            self.set_option(pycurl.USERAGENT, self.agent)
        if self.referer:
            self.set_option(pycurl.REFERER, self.referer)
        if self.proxy:
            self.set_option(pycurl.PROXY, self.proxy)
        if relative_url:
            self.set_option(pycurl.URL,os.path.join(self.base_url,relative_url))
        self.header.seek(0,0)
        self.payload = ""
        self.handle.perform()
        return self.payload

    def get(self, url="", params=None):
        """
        Get a url.
        """
        if params:
            url += "?" + urllib.urlencode(params)
        self.set_option(pycurl.HTTPGET, 1)
        return self.__request(url)

    def post(self, cgi, params):
        """
        Post a url.
        """
        self.set_option(pycurl.POST, 1)
        self.set_option(pycurl.POSTFIELDS, params)
        return self.__request(cgi)

    def body(self):
        """
        Get the payload from the latest operation.
        """
        return self.payload

    def info(self):
        """
        Get an info dictionary from the selected url.
        """
        self.header.seek(0,0)
        url = self.handle.getinfo(pycurl.EFFECTIVE_URL)
        if url[:5] == 'http:':
            self.header.readline()
            m = mimetools.Message(self.header)
        else:
            m = mimetools.Message(StringIO())
        #m['effective-url'] = url
        m['http-code'] = str(self.handle.getinfo(pycurl.HTTP_CODE))
        m['total-time'] = str(self.handle.getinfo(pycurl.TOTAL_TIME))
        m['namelookup-time'] = str(self.handle.getinfo(pycurl.NAMELOOKUP_TIME))
        m['connect-time'] = str(self.handle.getinfo(pycurl.CONNECT_TIME))
        #m['pretransfer-time'] = str(self.handle.getinfo(pycurl.PRETRANSFER_TIME))
        #m['redirect-time'] = str(self.handle.getinfo(pycurl.REDIRECT_TIME))
        #m['redirect-count'] = str(self.handle.getinfo(pycurl.REDIRECT_COUNT))
        #m['size-upload'] = str(self.handle.getinfo(pycurl.SIZE_UPLOAD))
        #m['size-download'] = str(self.handle.getinfo(pycurl.SIZE_DOWNLOAD))
        #m['speed-upload'] = str(self.handle.getinfo(pycurl.SPEED_UPLOAD))
        m['header-size'] = str(self.handle.getinfo(pycurl.HEADER_SIZE))
        m['request-size'] = str(self.handle.getinfo(pycurl.REQUEST_SIZE))
        #m['content-length-download'] = str(self.handle.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD))
        #m['content-length-upload'] = str(self.handle.getinfo(pycurl.CONTENT_LENGTH_UPLOAD))
        m['content-type'] = (self.handle.getinfo(pycurl.CONTENT_TYPE) or '').strip(';')
        #m['encoding'] = str(self.handle.getinfo(pycurl.ENCODING))
        return m

    @classmethod
    def print_options(cls):
        """
        Print selected options.
        """
        print '='*75 + '\n'
        print "[-]Verbose: On!"
        print "[-]Cookie:", cls.cookie
        print "[-]HTTP User Agent:", cls.agent
        print "[-]HTTP Referer:", cls.referer
        print "[-]Extra HTTP Headers:", cls.headers
        print "[-]Authentication Type:", cls.atype
        print "[-]Authentication Credentials:", cls.acred
        print "[-]Proxy:", cls.proxy
        print "[-]Timeout:", cls.timeout
        print "[-]Delaying:", cls.delay, "seconds"
        print "[-]Threads:", cls.threads
        print "[-]Retries:", cls.retries, '\n'

    def answered(self, check):
        """
        Check for occurence of a string in the payload from
        the latest operation.
        """
        return self.payload.find(check) >= 0

    def close(self):
        """
        Close the curl handle.
        """
        self.handle.close()
        self.header.close()
        self._closed = True

    def __del__(self):
        if not self._closed:
            self.close()