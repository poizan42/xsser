import optparse

class XSSerOptions(optparse.OptionParser):
    def __init__(self, *args):
        optparse.OptionParser.__init__(self, 
                           description='Cross site "scripter" is an automatic tool for pentesting XSS attacks against different applications. (See \033[1;37mREADME\033[1;m for more information)',
                           prog='XSSer.py',
                           version='\033[1;35mXSSer v0.7a\033[1;m - (Copyright - GPL3.0) - 2010 \033[1;35mby psy\033[1;m\n',
                           usage= '\npython XSSer.py [-u <url> |-i <file> |-d <dork>] [-p <postdata> |-g <getdata> |-c <crawling>] [OPTIONS] [Request] [Bypassing] [Techniques]\n')

        self.set_defaults(verbose=False, threads=1, retries=3, timeout=30)
        self.disable_interspersed_args()

        self.add_option("-v", "--verbose", action="store_true", dest="verbose", help="verbose (default NO)")
        #self.add_option("--update", action="store", dest="update", help="update XSSer tool (core+vectors)") 
        self.add_option("-w", action="store_true", dest="fileoutput", help="output results to file") 
	self.add_option("-s", action="store_true", dest="statistics", help="report some statistics")
        self.add_option("--short", action="store", dest="shorturls", help="generate shortered links (tinyurl, is.gd) ")

        group1 = optparse.OptionGroup(self, "*Target*",
        "At least one of these options has to be specified to set the source to get target urls from.")
        group1.add_option("-u", "--url", action="store", dest="url", help="Enter target(s) to audit") 
        group1.add_option("-i", action="store", dest="readfile", help="Read target URLs from a file")
        group1.add_option("-d", action="store", dest="dork", help="Process search engine dork results as target urls")
        group1.add_option("--De", action="store", dest="dork_engine", help="Search engine to use for dorking (scroogle, duck, altavista, bing)")
        self.add_option_group(group1)

        group2 = optparse.OptionGroup(self, "*HTTP(s) Connections*",
        "Testable parameter(s)")
	group2.add_option("-g", action="store", dest="getdata", help="Enter payload to audit using GET. (ex: '/menu.php?q=')")
	group2.add_option("-p", action="store", dest="postdata", help="Enter payload to audit using POST. (ex: 'foo=1&bar=')")
	group2.add_option("-c", action="store", dest="crawling", help="Crawl target hierarchy parameters (can be slow!)")
	group2.add_option("--Cw", action="store", dest="crawling_width", help="Number of urls to visit when crawling")
        self.add_option_group(group2)

        group3 = optparse.OptionGroup(self, "*Request*",
        "These options can be used to specify how to connect to the target url.") 
        group3.add_option("--cookie", action="store", dest="cookie", help="Try this HTTP Cookie header") 
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
       
        group4 = optparse.OptionGroup(self, "*Bypassing filters*",
        "These options can be used to bypass -XSS- filters on target code.")
        group4.add_option("--Str", action="store_true", dest="Str", help="Use method String.FromCharCode()")
        group4.add_option("--Une", action="store_true", dest="Une", help="Use function Unescape()")
        group4.add_option("--Hex", action="store_true", dest="Hex", help="Use Hexadecimal encoding")
        group4.add_option("--Hes", action="store_true", dest="Hes", help="Use Hexadecimal encoding, with semicolons")
        group4.add_option("--Dec", action="store_true", dest="Dec", help="Use Decimal encoding")
        group4.add_option("--Dwo", action="store_true", dest="Dwo", help="Encode vectors IP addresses in DWORD")
	group4.add_option("--Doo", action="store_true", dest="Doo", help="Encode vectors IP addresses in Octal")
        group4.add_option("--Mix", action="store_true", dest="Mix", help="Mix String.FromCharCode() and Unescape()")
	group4.add_option("--Cem", action="store", dest="Cem", help="Try Character Encoding mutations (ex: 'Hex,Str,Hex')")
        group4.add_option("--Fuzz", action="store_true", dest="fuzz", help="Try different XSS fuzzing vectors (from file)") 
        group4.add_option("--Anchor", action="store_true", dest="anchor", help="User anchor stealth (DOM shadows!)")
        self.add_option_group(group4)

        group5 = optparse.OptionGroup(self, "*Manual vectors*",
        "Try to inject -manually- your own payload.")
        group5.add_option("--payload", action="store", dest="script", help="OWN - Insert your XSS construction -manually-")
        group5.add_option("--Fr", action="store", dest="finalpayload", help="Final payload for the real attack")
        self.add_option_group(group5)
        
        group6 = optparse.OptionGroup(self, "*Techniques*",
        "Try to inject code using different techniques.")
      # group6.add_option("--Dcp", action="store_true", dest="dcp", help="DCP - Data Control Protocol injection, with fuzzing")     
      # group6.add_option("--Dom", action="store_true", dest="dom", help="DOM - Document Object Model Cross-Site Scripting")
        group6.add_option("--Coo", action="store_true", dest="coo", help="COO - Cross Site Scripting Cookie injection")
        group6.add_option("--Xsa", action="store_true", dest="xsa", help="XSA - Cross Site Agent Scripting")
        group6.add_option("--Xsr", action="store_true", dest="xsr", help="XSR - Cross Site Referer Scripting")
      # group6.add_option("--Xfs", action="store_true", dest="xfs", help="XFS - Cross Frame Scripting")
        group6.add_option("--Dos", action="store_true", dest="dos", help="DOS - XSS Denial of service (client) attack!!")
        self.add_option_group(group6)

    def get_options(self):
        (options, args) = self.parse_args()
        if (not options.url and not options.readfile and not options.dork): 
            print '='*75
            print  '\n', self.version
            print  self.description, '\n'
            print '='*75
            print  self.usage
            print "For \033[1;37mhelp\033[1;m use \033[1;37m-h\033[1;m or \033[1;37m--help\033[1;m\n"
            print '='*55
            return False
        return options

