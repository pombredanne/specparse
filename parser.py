# -*- coding: utf-8 -*-

import os
import re
from copy import copy

from .machine import FiniteMachine, State



__all__ = ('SPECParser, SPECParserError, SPECFile')


class SPECParserError(Exception):
    pass

class UnknownLineError(SPECParserError):
    pass

class InvalidLineError(SPECParserError):
    pass



class SPECFile(object):
    """
    Class representing parsed RPM SPEC file.
    """
    ALLOWED_KEYS = set(['name', 'version', 'release', 'url', 'license',
                        'summary', 'group', 'sources', 'patches',
                        'excludearchs', 'exclusivearchs', 'buildarchs',
                        'buildroot', 'buildrequires', 'buildconflicts',
                        'requires', 'provides', 'conflicts', 'obsoletes',
                        'defines', 'subpackages'])

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
        'directive': r'\%(description|package|files)\s*(\w*)',
        'section':   r'\%(prep|check|build|install|clean|changelog)',
        'scriptlet': (r'\%(pre|preun|post|postun|pretrans|posttrans)'
                      r'\s*(\-p)?(\s*.*)?'),
        'scl':       r'\%\{\?scl\:(.+)%}',
        'define':    r'\%(define|global)\s*([^\s]+)\s*([^\s]+)',
        'condition': r'\%(if|endif)\s*([\w\s\-\+\.\%\?\{\}\=\>\<]+)',
    }

    MAIN_TAG_REGEXPS = {
        'name':    r'Name:\s*([\w\-\s]+)',
        'version': r'Version:\s*([\w\-\s\.\%\?\{\}]+)',
        'release': r'Release:\s*([\w\-\s\.\%\?\{\}]+)',
        'url':     r'URL:\s*([\w\-\s\.\%\?\{\}]+)',
        'license': r'License:\s*([\w\-\s\.\+]+)',
        'source':  r'Source\d*:\s*([\w\-\s\.\%\?\{\}]+)',
        'patch':   r'Patch\d*:\s*([\w\-\s\.\%\?\{\}]+)',

        'buildarch':      r'BuildArch:\s*(\w+)',
        'buildroot':      r'BuildRoot:\s*([\w\s\-\.\/\%\?\{\}]+)',
        'buildrequires':  r'BuildRequires:\s*([\w\s\-\=\>\<\.]+)',
        'buildconflicts': r'BuildConflicts:\s*([\w\s\-\=\>\<\.]+)',
        'excludearch':    r'ExcludeArch:\s*(\w+)',
        'exclusivearch':  r'ExclusiveArch:\s*(\w+)',
    }

    TAG_REGEXPS = {
        'summary': r'Summary:\s*([^#]+)',
        'group':   r'Group:\s*([\w\s\/]+)',

        'requires':       r'Requires:\s*([\w\s\-\=\>\<\.]+)',
        'provides':       r'Provides:\s*([\w\s\-\=\>\<\.]+)',
        'conflicts':      r'Conflicts:\s*([\w\s\-\=\>\<\.]+)',
        'obsoletes':      r'Obsoletes:\s*([\w\s\-\=\>\<\.]+)',
    }

    @staticmethod
    def _transition(current_state, new_state, **kwargs):
        """
        Processing switch.
        """
        line = kwargs['line']
        self = kwargs['parser']
        if new_state == 'INIT':
            return self._process_init(line)
        elif new_state == 'TAG':
            return self._process_tag(line)
        elif newstate == 'DIR':
            return self._process_dir(line)
        elif newstate == 'SEC':
            return self._process_sec(line)
        elif newstate == 'EOF':
            return True
        else:
            return False

    MACHINE = FiniteMachine(
                State(name='INIT',
                      help_text='Initial defines',
                      next_states=['TAG', 'EOF'],
                      check_perms=[SPECParser._transition]),
                State(name='TAG',
                      help_text='Tag processing',
                      next_states=['DIR', 'SEC', 'EOF'],
                      check_perms=[SPECParser._transition]),
                State(name='DIR',
                      help_text='Directive processing',
                      next_states=['TAG', 'SEC', 'EOF'],
                      check_perms=[SPECParser._transition]),
                State(name='SEC',
                      help_text='Section and scriplet processing',
                      next_states=['TAG', 'DIR', 'EOF'],
                      check_perms=[SPECParser._transition]),
                State(name='EOF',
                      help_text='End of file',
                      next_states=[],
                      check_perms=[SPECParser._transition]))


    def __init__(self):
        comm = self.COM_REGEXPS.get('comment', r'(\#.*)')
        self._main_tags = {key: re.compile(r'^\s*%s%s$' % (exp, comm))
                           for key, exp in self.MAIN_TAG_REGEXPS.iteritems()}
        self._tags = {key: re.compile(r'^\s*%s%s$' % (exp, comm))
                      for key, exp in self.TAG_REGEXPS.iteritems()}
        self._other = {key: re.compile(r'^\s*%s$' % exp)
                       for key, exp in self.COM_REGEXPS.iteritems()}
        self._machine = copy(self.MACHINE)
        self._machine.set_state('INIT')
        self._block = None

    def _process_init(self, line):
        """
        Process initial defines, globals, scl macros. etc. Returns True if the
        processing was successful, otherwise returns False.
        """
        match = self._other['define'].search(line)
        if match:
            key = match.group(1)
            value = match.group(2)
            self._result.setdefault('defines', {})[key] = value
            return True
        if self._other['scl'].search(line):
            return True
        if self._other['condition'].search(line):
            return True
        return False

    def _process_tag(self, line):
        """
        Process all tags. Returns True if the processing was successful,
        otherwise returns False.
        """
        for key, exp in self._main_tags.iteritems():
            match = exp.search(line)
            if not match:
                continue
            self._result[key] = match.group(1).strip()
            return True

        if self._block and self._block.startswith('package:'):
            for key, exp in self._tags.iteritems():
                match = exp.search(line)
                if not match:
                    continue
                pkg = self._block[8:]
                self._result['subpackages'][pkg][key] = match.group(1).strip()
                return True
        return False

    def _process_dir(self, line):
        """
        Process directives such as %package, %files and description.
        Returns True if the processing was successful, otherwise returns False.
        """
        match = self._other['directive'].search(line)
        if match:
            self._block =

    def _process_sec(self, line):
        pass

    def parse(self, spec_file):
        is_file = hasattr(spec_file, 'readlines')
        _fname, _spec = is_file and (spec_file, spec_file.name) or \
                            (open(spec_file, 'r'), os.path.basename(spec_file))

        self._result = {}
        for line in _spec:
            current = self.machine.get_state()
            next_states = [i[1] for i in
                    self.machine.get_next_states_mapping(append_current=True)

            transition = False
            for state in next_states:
                if self._machine.change_state(state, line=line, parser=self)
                    transition = True
                    break
