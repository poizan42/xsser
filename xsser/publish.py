#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
Federated (full disclosure version) XSS pentesting.

Publish results on social networking sites. 
             
This implementation is for identi.ca (http://identi.ca)
and twitter (http://twitter.com/)

This bot is completly Public. All publised data will be accessed from Internet 

Please report your results using -automatic- format to create a good XSS pentesting Reporting Archive. 
Or try to create your own bot/s changing some configuration parameters and federate it (all us you want)
to this "2 first -replicants-: xsserbot01" ;) 
								             
xsserbot01: 
http://identi.ca/xsserbot01

xsserbot01(clone): 
http://twitter.com/xsserbot01

To launch you own -bot-, first create an account on identica/twitter, 
and after change this values with your data:

   - username = <identica username>
   - password = <identica password>

Dont forget to put your bot to "follow" other -replicants-.
If you dont know any, try this: xsserbot01

Happy "Cross" Federated Hacking. ;)

"""
import urllib2, urllib

class publisher(object):

    def __init__(self, xsser):
        # initialize main XSSer
        self.instance = xsser

    def send_to_identica(self, msg, username, password, url=None):
        if url is None:
            url = "http://identi.ca/api/statuses/update.xml"
        data = urllib.urlencode({'status':msg})
        passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, url, username, password)
        authhandler = urllib2.HTTPBasicAuthHandler(passman)
        opener = urllib2.build_opener(authhandler)
        urllib2.install_opener(opener)
        pagehandle = urllib2.urlopen(url, data)
        print pagehandle

if __name__ == "__main__":
    publish = publisher()
    publish.send_to_identica('XSSer a.ka Cross Site -Scripter- more info: http://xsser.sf.net', 'xsserbot01', '8vnVw8wvs', 'http://identi.ca/api/statuses/update.xml')

