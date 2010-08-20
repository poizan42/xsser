import urllib

class EncoderDecoder(object):
    """
    Class to help encoding and decoding strings with different hashing or
    encoding algorigthms..
    """
    # encdec functions:
    def __init__(self):
        self.encmap = { "Str" : lambda x : self._fromCharCodeEncode(x), 
                   "Hex" : lambda x : self._hexEncode(x),
                   "Hes" : lambda x : self._hexSemiEncode(x),
                   "Une" : lambda x : self._unEscape(x),
                   "Dec" : lambda x : self._decEncode(x),
                   "Mix" : lambda x : self._unEscape(_fromCharCodeEncode(x))
                   }

    def _fromCharCodeEncode(self, string):
        """
        Encode to string.
        """
        encoded=''
        for char in string:
                encoded=encoded+","+str(ord(char))
        return encoded[1:]

    def _hexEncode(self, string):
        """
        Encode to hex.
        """
        encoded=''
        for char in string:
                encoded=encoded+"%"+hex(ord(char))[2:]
        return encoded

    def _hexSemiEncode(self, string):
        """
        Encode to semi hex.
        """
        encoded=''
        for char in string:
                encoded=encoded+"&#x"+hex(ord(char))[2:]+";"
        return encoded

    def _decEncode(self, string):
        """
        Encode to decimal.
        """
        encoded=''
        for char in string:
                encoded=encoded+"&#"+str(ord(char))
        return encoded

    def _unEscape(self, string):
        """
        Escape string.
        """
        encoded=''
        for char in string:
                encoded=encoded+urllib.quote(char)
        return encoded

    def _ipDwordEncode(self, string):
        """
        Encode to dword.
        """
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
	
    def _ipOctalEncode(self, string):
	"""
        Encode to octal.
	"""
        encoded=''
        tblIP = string.split('.')
        # In the case it's not an IP
        if len(tblIP)<>4:
	        return 0
        octIP = map(lambda s: oct(int(s)).zfill(4), tblIP)
	return ".".join(octIP)


if __name__ == "__main__":
    encdec = EncoderDecoder()
    print encdec._ipOctalEncode("127.0.0.1")
    

