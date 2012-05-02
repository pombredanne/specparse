# -*- coding: utf-8 -*-

import re



class SPECParserError(Exception):
    pass


class SPECFile(object):
    """
    Class representing parsed RPM SPEC file.
    """
    ALLOWED_KEYS = set(['name', 'version', 'release', 'url', 'license',
                        'summary', 'group', 'sources', 'patches',
                        'excludearchs', 'exclusivearchs', 'buildarchs',
                        'buildroot', 'buildrequires', 'buildconflicts',
                        'requires', 'provides', 'conflicts', 'obsoletes'])

    def __init__(self, filename, **kwargs):
        self.filename = filename
        for key, value in kwargs:
            if key not in self.ALLOWED_KEYS:
                raise KeyError('Invalid SPEC file attribute: %s' % key)
            setattr(self, key, value)


class SPECParser(object):
    """
    Class for RPM SPEC file parsing.
    """
    COM_REGEXPS = {
        'comment':   r'(\#.*)',
        'directive': r'\%(description|package|files|changelog)\s*(\w*)',
        'section':   r'\%(prep|check|build|install|clean)',
        'scriptlet': (r'\%(pre|preun|post|postun|pretrans|posttrans)'
                      r'\s*(\-p)?(\s*.*)?'),
        'scl':       r'\%\{\?scl\:(.+)%}',
        'define':    r'\%(define|global)\s*([^\s]+)\s*([^\s]+)',
    }

    TAG_REGEXPS = {
        'name':    r'Name:\s*([\w\-\s]+)',
        'version': r'Version:\s*([\w\-\s\.\%\?\{\}]+)',
        'release': r'Release:\s*([\w\-\s\.\%\?\{\}]+)',
        'url':     r'URL:\s*([\w\-\s\.\%\?\{\}]+)',
        'license': r'License:\s*([\w\-\s\.\+]+)',
        'summary': r'Summary:\s*([^#]+)',
        'group':   r'Group:\s*([\w\s\/]+)',

        'source': r'Source\d*:\s*([\w\-\s\.\%\?\{\}]+)',
        'patch':  r'Patch\d*:\s*([\w\-\s\.\%\?\{\}]+)',

        'excludearch':    r'ExcludeArch:\s*(\w+)',
        'exclusivearch':  r'ExclusiveArch:\s*(\w+)',
        'buildarch':      r'BuildArch:\s*(\w+)',
        'buildroot':      r'BuildRoot:\s*([\w\s\-\.\/\%\?\{\}]+)',
        'buildrequires':  r'BuildRequires:\s*([\w\s\-\=\>\<\.]+)',
        'buildconflicts': r'BuildConflicts:\s*([\w\s\-\=\>\<\.]+)',
        'requires':       r'Requires:\s*([\w\s\-\=\>\<\.]+)',
        'provides':       r'Provides:\s*([\w\s\-\=\>\<\.]+)',
        'conflicts':      r'Conflicts:\s*([\w\s\-\=\>\<\.]+)',
        'obsoletes':      r'Obsoletes:\s*([\w\s\-\=\>\<\.]+)',
    }

    def __init__(self, spec_file):
        self._spec = hasattr(spec_file, 'readlines') and spec_file or \
                                                         open(spec_file, 'r')
        comm = self.COM_REGEXPS.get('comment', r'(\#.*)')
        self._tokens = {key: re.compile(r'^\s*%s%s$' % (exp, comm))
                        for key, exp in self.TAG_REGEXPS.iteritems()
                        if key not in ('comment', 'section')}


    def parse(self):
        pass
