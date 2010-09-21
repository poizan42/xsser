import urllib2
import traceback
urllib2.socket.setdefaulttimeout(5.0)
from BeautifulSoup import BeautifulSoup

DEBUG = 1

class Dorker(object):
    def __init__(self, engine='bing'):
        self._engine = engine

    def dork(self, search):
        """
        Perform a search and return links.

        Uses -bing- engine by default.

	(http://en.wikipedia.org/wiki/List_of_search_engines)
        """
        if self._engine == 'bing' or not self._engine:
            search_url = "http://www.bing.com/search?q=" + urllib2.quote(search)
        elif self._engine == 'scroogle':
            search_url = "http://www.scroogle.org/cgi-bin/nbbw.cgi?q=" + urllib2.quote(search)
        elif self._engine == 'altavista':
            search_url = "http://es.altavista.com/web/results?fr=altavista&itag=ody&q=" + urllib2.quote(search)
        elif self._engine == 'duck':
            search_url = "https://duckduckgo.com/?q=" + urllib2.quote(search)
        elif self._engine == 'baidu':
            search_url = "http://www.baidu.com/s?wd=" + urllib2.quote(search)
        elif self._engine == 'yandex':
            search_url = "http://yandex.ru/yandsearch?text=" + urllib2.quote(search)
        elif self._engine == 'yebol':
            search_url = "http://www.yebol.com/a.jsp?x=0&y=0&key=" + urllib2.quote(search)
        elif self._engine == 'youdao':
            search_url = "http://www.youdao.com/search?q=" + urllib2.quote(search)
        elif self._engine == 'cuil':
            search_url = "http://www.cuil.com/search?q=" + urllib2.quote(search)
        elif self._engine == 'ask':
            search_url = "http://www.ask.com/web?q=" + urllib2.quote(search)
        try:
            url = urllib2.urlopen(urllib2.Request(search_url,
                                                  headers={'User-Agent':
                            "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"}))
        except urllib2.URLError, e:
            if DEBUG:
                traceback.print_exc()
            raise Exception("Internal error dorking: " + e.message)
        html_data = url.read()
        html_data = html_data.replace(">",">\n")
        html_data = html_data.replace("target=_",'target="_')
        html_data = html_data.replace('\ >','/>')
        html_data = html_data.replace('\>','/>')
        html_data = html_data.replace('"">','">')
        html_data = html_data.replace('</scr"+"ipt>','</script>')
        content_type = url.headers['content-type']
        encoding = content_type.split(";")[1].split("=")[1].strip()
        try:
            soup = BeautifulSoup(html_data, fromEncoding=encoding)
        except Exception, e:
            traceback.print_exc()
            print html_data
            raise Exception("Internal error dorking:" + e.message)

        links = soup.findAll('a')
        found_links = []
        for link in links:
            try:
                href = str(link['href'].encode('utf-8'))
            except KeyError:
                # this link has no href
                pass
            else:
                if not href.startswith("/") and not "microsofttranslator" in href and not "bingj" in href and not "live.com" in href and not "scroogle" in href:
                    found_links.append(href)
        return found_links

if __name__ == '__main__':
    dork = Dorker()
    for url in dork.dork("falluyah bombing"):
        print url

