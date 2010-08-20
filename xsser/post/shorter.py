"""
Post processing filter to make reservations on shortered links.
"""

import urllib
import pycurl
from cStringIO import StringIO
from BeautifulSoup import BeautifulSoup

class ShortURLReservations(object):
    #options = [['-foo!', 'do stuff']]
    def __init__(self, service='tinyurl'):
        self._service = service
        self._parse_shortener()
        self._extra = {}

    def _parse_shortener(self):
        """
	List of valid links shorterers 
	"""
        if self._service == 'tinyurl' or not self._service:
            self._url = 'http://tinyurl.com/create.php'
            self._par = 'url'
            self._method = 'get'
        elif self._service == 'bit.ly':
            self._url = 'http://bit.ly'
            self._par = 'u'
            self._method = 'get'
        elif self._service == 'is.gd':
            self._url = 'http://is.gd/create.php'
            self._par = 'URL'
            self._method = 'post'
	
    def process_url(self, url):
        dest = urllib.urlencode({self._par: url})
        out = StringIO()
        c = pycurl.Curl()
        if self._method == 'post':
            c.setopt(c.POST, 1)
            c.setopt(c.POSTFIELDS, dest)
            target = self._url
        else:
            target = self._url + '?' + dest
        c.setopt(c.URL, target)
        c.setopt(c.FOLLOWLOCATION, 1)
        c.setopt(c.WRITEFUNCTION, out.write)
        c.perform()
        c.close()

        soup = BeautifulSoup(out.getvalue())
        if self._service == 'tinyurl':
            return soup.findAll('blockquote')[1].findAll('a')[0]['href']
        elif self._service == 'bit.ly':
            #print out.getvalue()
	    xsrf = soup.findAll('input', {'name':'_xsrf'})[0]['value']
            #print soup.findAll('div', 'linkCapsule_unauth_shortenedLink')[0]
            return soup.findAll('div', 'unauth_long_link')[0].findAll('a')[0]['href']
        elif self._service == 'is.gd':
            return soup.findAll('input',{'id':'short_url'})[0]['value']

if __name__ == "__main__":
    shortener = ShortURLReservations('tinyurl')
    print shortener.process_url('http://slashdot.org?foo')
    shortener = ShortURLReservations('is.gd')
    print shortener.process_url('http://slashdot.org?foo')
    shortener = ShortURLReservations('bit.ly')
    print shortener.process_url('http://slashdot.org?foo')
