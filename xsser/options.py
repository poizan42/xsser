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
import optparse

class XSSerOptions(optparse.OptionParser):
    def __init__(self, *args):
        optparse.OptionParser.__init__(self, 
                           description='Cross Site "Scripter" is an automatic tool for pentesting XSS attacks against different applications.',
                           prog='XSSer.py',
			   version='\n\033[1;35mXSSer v1.0\033[1;m: "The Mosquito" // (2010) - (Copyright - GPLv3.0) // \033[1;35mby psy\033[1;m\n',
                           usage= '\n./XSSer.py [OPTIONS] [-u <url> |-i <file> |-d <dork>] [-g <get> |-p <post> |-c <crawl>] [Request(s)] [Vector(s)] [Bypasser(s)] [Technique(s)] [Final Injection(s)]')

        self.set_defaults(verbose=False, threads=1, retries=3, timeout=30)
        self.disable_interspersed_args()

        self.add_option("-v", "--verbose", action="store_true", dest="verbose", help="verbose (default: no)")
        self.add_option("-s", action="store_true", dest="statistics", help="show statistics with all injection attempts responses")
        self.add_option("-w", action="store_true", dest="fileoutput", help="output all results directly to template (XSSlist.dat)")
        self.add_option("--xml", action="store", dest="filexml", help="output 'positives' to aXML file (--xml filename.xml)")
        self.add_option("--publish", action="store_true", dest="tweet", help="output 'positives' to Social Networks (identi.ca)")
        self.add_option("--short", action="store", dest="shorturls", help="output -final code- shortered (tinyurl, is.gd) ")
        self.add_option("--imx", action="store", dest="imx", help="create a false image with XSS code embedded")
        self.add_option("--fla", action="store", dest="flash", help="create a false .swf file with XSS code embedded")
        self.add_option("--check", action="store_true", dest="check", help="send a hash to pre-check if target repeats all content recieved (usefull to reduce 'false positive' results)")
        self.add_option("--launch", action="store_true", dest="launch_browser", help="launch a browser at the end, with each 'positive' final code injection(s) discovered")

        group1 = optparse.OptionGroup(self, "*Select Target(s)*",
        "At least one of these options has to be specified to set the source to get target(s) urls from. You need to choose to run XSSer:")
        group1.add_option("-u", "--url", action="store", dest="url", help="Enter target(s) to audit") 
        group1.add_option("-i", action="store", dest="readfile", help="Read target urls from a file")
        group1.add_option("-d", action="store", dest="dork", help="Process search engine dork results as target urls")
        group1.add_option("--De", action="store", dest="dork_engine", help="Search engine to use for dorking (duck, altavista, bing, baidu, yandex, yebol, youdao, google, yahoo)")
        self.add_option_group(group1)

        group2 = optparse.OptionGroup(self, "*Select type of HTTP/HTTPS Connection(s)*",
        "These options can be used to specify which parameter(s) we want to use like payload to inject code.")
        group2.add_option("-g", action="store", dest="getdata", help="Enter payload to audit using GET. (ex: '/menu.php?q=')")
        group2.add_option("-p", action="store", dest="postdata", help="Enter payload to audit using POST. (ex: 'foo=1&bar=')")
        group2.add_option("-c", action="store", dest="crawling", help="Crawl target hierarchy parameters (can be slow!)")
        group2.add_option("--Cw", action="store", dest="crawler_width", help="Number of urls to visit when crawling (deeping level)")
        self.add_option_group(group2)

        group3 = optparse.OptionGroup(self, "*Configure Request(s)*",
        "These options can be used to specify how to connect to target(s) payload(s). You can select multiple:") 
        group3.add_option("--cookie", action="store", dest="cookie", help="Change your HTTP Cookie header") 
        group3.add_option("--user-agent", action="store", dest="agent", help="Change your HTTP User-Agent header (default SPOOFED)") 
        group3.add_option("--referer", action="store", dest="referer", help="Use another HTTP Referer header (default NONE)") 
        group3.add_option("--headers", action="store", dest="headers", help="Extra HTTP headers newline separated")
        group3.add_option("--auth-type", action="store", dest="atype", help="HTTP Authentication type (value Basic or Digest)") 
        group3.add_option("--auth-cred", action="store", dest="acred", help="HTTP Authentication credentials (value name:password)")  
        group3.add_option("--proxy", action="store", dest="proxy", help="Use proxy server (tor: http://localhost:8118)") 
        group3.add_option("--timeout", action="store", dest="timeout", type="int", help="Select your Timeout (default 30)") 
        group3.add_option("--delay", action="store", dest="delay", type="int", help="Delay in seconds between each HTTP request (default 8)") 
        group3.add_option("--threads", action="store", dest="threads", type="int", help="Maximum number of concurrent HTTP requests (default 1)") 
        group3.add_option("--retries", action="store", dest="retries", type="int", help="Retries when the connection timeouts (default 3)") 
        self.add_option_group(group3)

        group4 = optparse.OptionGroup(self, "*Select Vector(s)*",
        "These options can be used to specify a XSS vector source code to inject in each payload. Important, if you don't want to try to inject a common XSS vector, used by default. Choose only one option:")
        group4.add_option("--payload", action="store", dest="script", help="OWN  - Insert your XSS construction -manually-")
        group4.add_option("--auto", action="store_true", dest="fuzz", help="AUTO - Insert XSSer 'reported' vectors from file")
        self.add_option_group(group4)
       
        group5 = optparse.OptionGroup(self, "*Select Bypasser(s)*",
        "These options can be used to encode selected vector(s) to try to bypass all possible anti-XSS filters on target(s) code and some IPS rules, if the target use it. Also, can be combined with other techniques to provide encoding:")
        group5.add_option("--Str", action="store_true", dest="Str", help="Use method String.FromCharCode()")
        group5.add_option("--Une", action="store_true", dest="Une", help="Use function Unescape()")
        group5.add_option("--Mix", action="store_true", dest="Mix", help="Mix String.FromCharCode() and Unescape()")
        group5.add_option("--Dec", action="store_true", dest="Dec", help="Use Decimal encoding")
        group5.add_option("--Hex", action="store_true", dest="Hex", help="Use Hexadecimal encoding")
        group5.add_option("--Hes", action="store_true", dest="Hes", help="Use Hexadecimal encoding, with semicolons")
        group5.add_option("--Dwo", action="store_true", dest="Dwo", help="Encode vectors IP addresses in DWORD")
        group5.add_option("--Doo", action="store_true", dest="Doo", help="Encode vectors IP addresses in Octal")
        group5.add_option("--Cem", action="store", dest="Cem", help="Try -manually- different Character Encoding mutations (reverse obfuscation: good) -> (ex: 'Mix,Une,Str,Hex')")
        self.add_option_group(group5)

        group6 = optparse.OptionGroup(self, "*Special Technique(s)*",
        "These options can be used to try to inject code using different type of XSS techniques. You can select multiple:")
        group6.add_option("--Coo", action="store_true", dest="coo", help="COO - Cross Site Scripting Cookie injection")
        group6.add_option("--Xsa", action="store_true", dest="xsa", help="XSA - Cross Site Agent Scripting")
        group6.add_option("--Xsr", action="store_true", dest="xsr", help="XSR - Cross Site Referer Scripting")
        group6.add_option("--Dcp", action="store_true", dest="dcp", help="DCP - Data Control Protocol injections")
        group6.add_option("--Dom", action="store_true", dest="anchor", help="DOM - Use Anchor Stealth (DOM shadows!)")
        self.add_option_group(group6)

        group7 = optparse.OptionGroup(self, "*Select Final injection(s)*",
        "These options can be used to specify the final code to inject in vulnerable target(s). Important, if you want to exploit on-the-wild your discovered vulnerabilities. Choose only one option:")
        group7.add_option("--Fp", action="store", dest="finalpayload", help="OWN    - Insert your final code to inject -manually-")
        group7.add_option("--Fr", action="store", dest="finalremote", help="REMOTE - Insert your final code to inject -remotelly-")
        group7.add_option("--B64", action="store_true", dest="b64", help="B64    - Base64 code encoding in META tag (rfc2397)")
        group7.add_option("--Dos", action="store_true", dest="dos", help="DOS    - XSS Denial of service (client) attack!!")
        self.add_option_group(group7)
        
        group8 = optparse.OptionGroup(self, "*Special Final injection(s)*",
        "These options can be used to execute some 'special' injection(s) in vulnerable target(s). You can select multiple and combine with your final code:")
        group8.add_option("--Onm", action="store_true", dest="onm", help="ONM - Use onMouseMove() event to inject code")
        group8.add_option("--Ifr", action="store_true", dest="ifr", help="IFR - Use <iframe> source tag to inject code")
        self.add_option_group(group8)

    def get_options(self):
        (options, args) = self.parse_args()
        if (not options.url and not options.readfile and not options.dork and not options.imx and not options.flash and not options.check): 
            print '='*75
            print  self.version
            print  self.description, '\n'
            print '='*75
            print "\nFor \033[1;37mhelp\033[1;m use \033[1;37m-h\033[1;m or \033[1;37m--help\033[1;m\n"
            print '='*55
            return False
        return options

