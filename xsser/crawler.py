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
import sys
import cgi
import urllib
import urllib2
from collections import defaultdict
from BeautifulSoup import BeautifulSoup

class Crawler(object):
    """
    Crawler class.

    Crawls a webpage looking for url arguments.
    Dont call from several threads! You should create a new one
    for every thread.
    """
    def __init__(self, curlwrapper=None):
        # verbose: 0-no printing, 1-prints dots, 2-prints full output
        self.verbose = 2
        if curlwrapper:
            self.curl = curlwrapper()

    def _find_args(self, url):
        """
        find parameters in given url.
        """
        parsed = urllib2.urlparse.urlparse(url)
        qs = cgi.parse_qs(parsed.query)
        if parsed.scheme:
            path = parsed.scheme + "://" + parsed.netloc + parsed.path
        else:
            path = parsed.netloc + parsed.path
        for key in qs:
            zipped = zip(*self._found_args[key])
            if not zipped or not path in zipped[0]:
                self._found_args[key].append([path, url])

    def crawl(self, path, depth=3, width=0):
        """
        setup and perform a crawl on the given url.
        """
        if self.verbose == 2:
            print "crawling: " + path
        self._max = depth
        self._path = path
        self._crawled = []
        self._width = width
        self._found_args = defaultdict(list)
        self._crawl(path, depth, width)
        attack_urls = []
        for arg_name, urls in self._found_args.iteritems():
            for path, url in urls:
                parsed = urllib2.urlparse.urlparse(url)
                qs = cgi.parse_qs(parsed.query)
                qs_joint = {}
                for key, val in qs.iteritems():
                    qs_joint[key] = val[0]
                attack_qs = dict(qs_joint)
                attack_qs[arg_name] = "PAYLOAD"
                attack_url = path + '?' + urllib.urlencode(attack_qs)
                attack_urls.append(attack_url)
        return attack_urls

    def _crawl(self, path, depth=3, width=0):
        """
        perform a crawl on the given url.

        this function downloads and looks for links.
        """
        if (width):
            self._width -= 1
            if (self._width < 0):
                return
        self._crawled.append(path)
        html_data = self.curl.get(path)
        content_type = self.curl.info().get('content-type', None)
        try:
            encoding = content_type.split(";")[1].split("=")[1].strip()
        except:
            encoding = None
        try:
            soup = BeautifulSoup(html_data, fromEncoding=encoding)
        except:
            print html_data
            return self._found_args
        soups = soup.findAll('a')
        if self.verbose == 2:
            print " "*(self._max-depth), path, len(soups)
        elif self.verbose:
            sys.stdout.write(".")
            sys.stdout.flush()
        for a in soups:
            try:
                href = str(a['href'].encode('utf-8'))
            except KeyError:
                # this link has no href
                pass
            if not href.startswith('http'):
                if not href.startswith('/'):
                    href = path + '/' + href
                else:
                    href = path + href
            else:
                href = href
            self._check_url(href, depth, width)
        return self._found_args

    def _check_url(self, href, depth, width):
        """
        process the given url for a crawl
        check to see if we have to continue crawling on the given url.
        """
        if href.startswith(self._path):
            self._find_args(href)
        if depth > 0:
            if self.verbose == 2:
                print " "*(self._max-depth) + " try: " + href
        if href.startswith(self._path) and not href in self._crawled:
            if (depth>0):
                if self.verbose == 2:
                    print " "*(self._max-depth) + " do: " + href
                try:
                    self._crawl(href, depth-1, width)
                except urllib2.URLError:
                    if self.verbose == 2:
                        print "couldnt open url", href
                    elif self.verbose:
                        sys.stdout.write("*")
                        sys.stdout.flush()
                    return

if __name__ == "__main__":
    c = Crawler()
    print c.crawl("https://darknet.lorea.cc", 1)
    #for k in c._found_args:
        #    print k, c._found_args[k]
