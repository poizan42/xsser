#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:

import sys
from xsser.main import XSSer
        
if __name__ == "__main__":
    app = XSSer()
    options = app.create_options()
    if not options:
        sys.exit()
    app.set_options(options)
    app.run()


