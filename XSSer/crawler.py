#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
# vim: ai et sw=4 ts=4 fileencodings=iso-8859-15
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012 psy <root@lordepsylon.net> - <epsylon@riseup.net>

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
import urlparse
import pycurl
import time
import traceback
import curlcontrol
import threadpool
import itertools
from Queue import Queue
from collections import defaultdict
from BeautifulSoup import BeautifulSoup

class EmergencyLanding(Exception):
    pass

class Crawler(object):
    """
    Crawler class.

    Crawls a webpage looking for url arguments.
    Dont call from several threads! You should create a new one
    for every thread.
    """
    def __init__(self, parent, curlwrapper=None, crawled=None, pool=None):
        # verbose: 0-no printing, 1-prints dots, 2-prints full output
        self.verbose = 0
        self._parent = parent
        self._to_crawl = []
        self._parse_external = True
        self._requests = []
        self._ownpool = False
        self._reporter = None
        self._armed = True
        self._poolsize = 10
        self._found_args = defaultdict(list)
        self.pool = pool
        if crawled:
            self._crawled = crawled
        else:
            self._crawled = []
        if curlwrapper:
            self.curl = curlwrapper
        else:
            self.curl = curlcontrol.Curl

    def report(self, msg):
        if self._reporter:
            self._reporter.report(msg)
        else:
            print msg

    def set_reporter(self, reporter):
        self._reporter = reporter

    def _find_args(self, url, usePost, postVars):
        """
        find parameters in given url.
        """
        parsed = urllib2.urlparse.urlparse(url)
        qs = cgi.parse_qs(parsed.query)
        if parsed.scheme:
            path = parsed.scheme + "://" + parsed.netloc + parsed.path
        else:
            path = parsed.netloc + parsed.path
        combined_args = ((q, None) for q in qs)
        if usePost:
            combined_args = itertools.chain(combined_args, ((None, p) for p in postVars))
        combined_args = list(combined_args)
        for (arg_name, parg_name) in combined_args:
            key = (arg_name, parg_name, parsed.netloc, usePost)
            zipped = zip(*self._found_args[key])
            if not zipped or not (path, usePost) in zipped[0]:
                self._found_args[key].append([(path, usePost), url])
                self.generate_result(arg_name, path, url, usePost, parg_name, postVars)
        ncurrent = sum(map(lambda s: len(s), self._found_args.values()))
        if ncurrent >= self._max:
            self._armed = False

    def cancel(self):
        self._armed = False

    def crawl(self, path, depth=3, width=0, local_only=True, getdata=True, postdata=False, allowpost=None):
        """
        setup and perform a crawl on the given url.
        """
        if not self._armed:
            return []
        if not allowpost and postdata:
            allowpost = True
        if None in locals().itervalues():
            args = locals()
            raise TypeError("NoneType is illegal for the arguments " + ",".join(
                (k for k in args.iterkeys() if args[k] == None)))

        self.getdata = getdata
        self.postdata = postdata
        self.allowpost = allowpost
        parsed = urllib2.urlparse.urlparse(path)
        basepath = parsed.scheme + "://" + parsed.netloc
        self._parse_external = not local_only
        if not self.pool:
            self.pool = threadpool.ThreadPool(self._poolsize)
        if self.verbose == 2:
            self.report("crawling: " + path)
        if width == 0:
            self._max = 1000000000
        else:
            self._max = int(width)
        self._path = path
        self._depth = depth
        attack_urls = []
        if not self._parent._landing and self._armed:
            self._crawl(basepath, path, depth, width)
            # now wait until we're done processing
            #while not self._parent._landing and self._requests and self._armed:
                #    if self._ownpool:
                    #    try:
                        #    self.pool.poll()
                        #except threadpool.NoResultsPending:
                            #break
                            # time.sleep(0.1)
            # now parse all found items
            if self._ownpool:
                self.pool.dismissWorkers(len(self.pool.workers))
                self.pool.joinAllDismissedWorkers()
        self.report("Finished crawl on " + path + " found " + str(len(attack_urls)) + " results" )
        return attack_urls

    def shutdown(self):
        if self._ownpool:
            self.pool.dismissWorkers(len(self.pool.workers))
            self.pool.joinAllDismissedWorkers()

    def generate_result(self, arg_name, path, url, usePost, pvName, postVars):
        if arg_name != None:
            parsed = urllib2.urlparse.urlparse(url)
            qs = cgi.parse_qs(parsed.query)
            attack_qs = dict((key, val[-1]) for key, val in qs.iteritems())
            attack_qs[arg_name] = "VECTOR"
            attack_url = path + '?' + urllib.urlencode(attack_qs)
        else:
            attack_url = url
        if usePost:
            if pvName != None:
                attack_ps = dict(postVars)
                attack_ps[pvName] = "VECTOR"
                attack_ps_enc = urllib.urlencode(attack_ps)
            else:
                attack_ps_enc = urllib.urlencode(postVars)
        else:
            attack_ps_enc = None
        if not (attack_url, attack_ps_enc) in self._parent.crawled_urls:
            self._parent.crawled_urls.append((attack_url, attack_ps_enc))

    def _crawl(self, basepath, path, depth=3, width=0, usePost = False, postVars = {}):
        """
        perform a crawl on the given url.

        this function downloads and looks for links.
        """
        self._crawled.append((path, usePost, postVars if usePost else None))
        if not path.startswith("http"):
            return

        def _cb(request, result):
            self._get_done(depth, width, request, result)

        self._requests.append((path, usePost, postVars))
        self.pool.addRequest(self._curl_main, [[
                             path, depth, width, basepath, usePost, postVars]],
                             self._get_done_dummy, self._get_error)

    def _curl_main(self, pars):
        path, depth, width, basepath, usePost, postVars = pars
        if not self._armed or len(self._parent.crawled_urls) >= self._max:
            raise EmergencyLanding
        c = self.curl()
        c.set_timeout(5)
        try:
            if usePost:
                res = c.post(path, urllib.urlencode(postVars))
            else:
                res = c.get(path)
        except Exception as error:
            c.close()
            del c
            raise error
        c_info = c.info().get('content-type', None)
        c.close()
        del c
        self._get_done(basepath, depth, width, path, res, c_info, usePost, postVars)
        #return res, c_info

    def _get_error(self, request, error):
        path, depth, width, basepath, usePost, postVars = request.args[0]
        e_type, e_value, e_tb = error
        if e_type == pycurl.error:
            errno, message = e_value.args
            if errno == 28:
                print("requests pyerror -1")
                self.enqueue_jobs()
                self._requests.remove((path, usePost, postVars))
                return # timeout
            else:
                self.report('crawler curl error: '+message+' ('+str(errno)+')')
        elif e_type == EmergencyLanding:
            pass
        else:
            traceback.print_tb(e_tb)
            self.report('crawler error: '+str(e_value)+' '+path)
        if not e_type == EmergencyLanding:
            for reporter in self._parent._reporters:
                reporter.mosquito_crashed(path, str(e_value))
        self.enqueue_jobs()
        self._requests.remove((path, usePost, postVars))

    def _emergency_parse(self, html_data, start=0):
        links = set()
        pos = 0
        data_len = len(html_data)
        while pos < data_len:
            if len(links)+start > self._max:
                break
            pos = html_data.find("href=", pos)
            if not pos == -1:
                sep = html_data[pos+5]
                if sep == "h":
                    pos -= 1
                    sep=">"
                href = html_data[pos+6:html_data.find(sep, pos+7)].split("#")[0]
                pos = pos+1
                links.add(href)
            else:
                break
        return map(lambda s: {'href': s}, links)

    def _get_done_dummy(self, request, result):
        #print(request.args)
        #print("PATH",request.args[0][0],len(self._requests))
        #print("\n".join(self._requests))
        path, depth, width, basepath, usePost, postVars = request.args[0]
        self.enqueue_jobs()
        self._requests.remove((path, usePost, postVars))
            #if not self._requests:
                #self._armed = False

    def enqueue_jobs(self):
        if len(self.pool.workRequests) < int(self._max/2):
            while self._to_crawl:
                next_job = self._to_crawl.pop()
                self._crawl(**next_job)

    # percent encodes everything that is not non-whitespace printable ascii,
    # as this is what browsers usually do with urls.
    def _percent_encode_nonpascii(self, url):
        encUrl = url.encode('utf-8') if isinstance(url, unicode) else url
        return "".join(
            chr(ord(c)) if ord(c) <= 0x7E and ord(c) >= 0x21
            else "%%%02X" % ord(c)
            for c in url)

    def _dict_uniToUtf8(self, d):
        return dict(
            (v.encode('utf-8') if isinstance(v, unicode) else v for v in kv)
            for kv in d.iteritems())

    def _append_pars(self, url, pars):
        url = self._percent_encode_nonpascii(url)
        parsed = urllib2.urlparse.urlparse(url)
        qs = cgi.parse_qs(parsed.query)
        qs2 = dict(((kv[0], kv[1][-1]) for kv in qs.iteritems()))
        pars2 = self._dict_uniToUtf8(pars)
        qs2.update(pars2)
        enc = urllib.urlencode(pars2)
        newParsed = list(parsed)
        newParsed[4] = enc
        return urllib2.urlparse.urlunparse(newParsed)

    #def _get_done(self, depth, width, request, result):
    def _get_done(self, basepath, depth, width, path, html_data, content_type,
                  requestPostUsed, requestPostVars):
        #print("get result")
        #html_data, content_type = result
        #path = request.args[0]
        if not self._armed or len(self._parent.crawled_urls) >= self._max:
            raise EmergencyLanding

        try:
            encoding = content_type.split(";")[1].split("=")[1].strip()
        except:
            encoding = None

        try:
            soup = BeautifulSoup(html_data, fromEncoding=encoding)
            links = None
        except:
            soup = None
            links = self._emergency_parse(html_data)

        for reporter in self._parent._reporters:
            reporter.start_crawl(path)

        if not links and soup:
            links = soup.findAll('a')
            forms = soup.findAll('form')

            for form in forms:
                pars = {}
                if form.has_key("method"):
                    method = form["method"].lower()
                else:
                    method = "get"
                if method != "get" and method != "post":
                    self.report("Form with unsupported method '" + method + "'. Falling back to GET.")
                    method = "get"
                    continue
                if form.has_key("action"):
                    action_path = urlparse.urljoin(path, form["action"])
                else:
                    action_path = path
                for input_par in form.findAll('input'):
                    if not input_par.has_key("name"):
                        continue
                    value = "foo"
                    if input_par.has_key("value") and input_par["value"]:
                        value = input_par["value"]
                    pars[input_par["name"]] = value
                for input_par in form.findAll('select'):
                    pars[input_par["name"]] = "1"
                if pars and method == "get":
                    links.append({"url": self._append_pars(action_path, pars), "method":method})
                else:
                    if not pars:
                        self.report("form with no pars")
                    links.append({"url":action_path, "method":method, "pars":pars})
            links += self._emergency_parse(html_data, len(links))
        if self.verbose == 2:
            self.report(" "*(self._depth-depth) + path +" "+ str(len(links)))
        elif self.verbose:
            sys.stdout.write(".")
            sys.stdout.flush()
        if len(links) > self._max:
            links = links[:self._max]
        for a in links:
            if 'href' in a:
                href = a['href']
            elif 'url' in a:
                href = a['url']
            else:
                continue
            href = self._percent_encode_nonpascii(href)
            if 'method' in a:
                method = a['method']
            else:
                method = 'get'
            if method == 'post' and 'pars' in a:
                postVars = self._dict_uniToUtf8(a['pars'])
            else:
                postVars = {}
            if href.startswith("javascript") or href.startswith('mailto:'):
                continue
            href = urlparse.urljoin(path, href)
            if not href.startswith("http"):
                continue
            href = href.split('#',1)[0]
            scheme_rpos = href.rfind('http://')
            if not scheme_rpos in [0, -1]:
                # looks like some kind of redirect so we try both too ;)
                href1 = href[scheme_rpos:]
                href2 = href[:scheme_rpos]
                self._check_url(basepath, path, href1, depth, width)
                self._check_url(basepath, path, href2, depth, width)
            self._check_url(basepath, path, href, depth, width,
                self.allowpost and method == "post", postVars)
        return self._found_args

    def _check_url(self, basepath, path, href, depth, width, usePost = False, postVars = {}):
        """
        process the given url for a crawl
        check to see if we have to continue crawling on the given url.
        """
        if usePost == None:
            raise TypeError
        do_crawling = self._parse_external or href.startswith(basepath)
        if do_crawling and not (href, usePost, postVars if usePost else None) in self._crawled:
            self._find_args(href, usePost, postVars)
            for reporter in self._parent._reporters:
                reporter.add_link(path, href)
            if self._armed and depth>0:
                #if self.verbose == 2:
                    #    print " "*(self._max-depth) + " do: " + href
                if len(self._to_crawl) < self._max:
                    self._to_crawl.append({
                        'basepath' : basepath,
                        'path': href,
                        'depth': depth-1,
                        'width': width,
                        'usePost': usePost,
                        'postVars': postVars})
                    #self._crawl(basepath, href, depth-1, width)

if __name__ == "__main__":
    class FakeParent(object):
        _reporters = []
        crawled_urls =  []
        _landing = False
    for n in [100,200,300,400,500]:
        c = Crawler(FakeParent())
        print("\ntesting %s\n"%(n))
        ress = c.crawl("https://n-1.cc", 3, n, True)
        if len(ress) >= n:
            print("\n%s ok -> %s"%(n, len(ress)))
    print("TOTAL:", len(ress))
    #for k in c._found_args:
        #    print k, c._found_args[k]
