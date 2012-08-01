# -*- coding: utf-8 -*-

import os
import re
from copy import copy

from .machine import FiniteMachine, State
import pdb


__all__ = ('SPECParser', 'SPECParserError', 'SPECFile')


class SPECParserError(Exception):
    pass

class UnknownLineError(SPECParserError):
    pass

class InvalidLineError(SPECParserError):
    pass


class BaseDefault(object):
    pass

class SPECFile(object):
    """
    Class representing parsed RPM SPEC file.
    """
    ALLOWED_KEYS = {'name', 'version', 'release', 'url', 'license', 'summary',
                    'group', 'sources', 'patches', 'excludearchs', 'exclusivearchs',
                    'buildarch', 'buildroot', 'buildrequires', 'buildconflicts',
                    'requires', 'provides', 'conflicts', 'obsoletes', 'defines',
                    'subpackages', 'files', 'prep', 'check', 'build', 'install',
                    'clean', 'changelog', 'description', 'pre', 'preun', 'post',
                    'postun', 'pretrans', 'posttrans'}
    SEQUENCE_KEYS = ('sources', 'patches', 'buildrequires', 'buildconflicts',
                     'conflicts', 'obsoletes', 'subpackages')
    SPECIAL_KEYS = ('defines',)

    class ValueFormatter(object):
        MACRO_REGEXPS = (r'\%\{\??([^\{\%]*)\}',)
        def __init__(self):
            self._macros = [re.compile(i) for i in self.MACRO_REGEXPS]

        def format_sequence(self, owner, value):
            return [self.format(owner, i) for i in value]

        def format(self, owner, value):
            val = str(value)
            for macro in self._macros:
                for match in macro.finditer(val):
                    # try to find value in defines and globals
                    attr = owner.defines.get(match.group(1), None)
                    # try to find value in SPEC values
                    if attr is None:
                        attr = getattr(owner, match.group(1), None)
                    if attr is None:
                        continue
                    val = re.sub(match.group(0), attr, val)
            return val


    def __init__(self, filename, **kwargs):
        print kwargs.keys()
        self._formatter = self.ValueFormatter()
        self.filename = filename
        for key, value in kwargs.iteritems():
            if key not in self.ALLOWED_KEYS:
                raise KeyError('Invalid SPEC file attribute: %s' % key)
        self._values = kwargs
        self.plain = False

    def __getattr__(self, key, default=BaseDefault()):
        """
        Returns either plain parsed value or formatted value depending
        to plain attribute.
        """
        try:
            print self._values.keys()
            value = self._values[key]
        except KeyError:
            if isinstance(default, BaseDefault):
                raise KeyError('Unknown SPEC tag')
            return default
        if self.plain or key in self.SPECIAL_KEYS:
            return value
        if key in self.SEQUENCE_KEYS:
            return self._formatter.format_sequence(self, value)
        return self._formatter.format(self, value)


def _transition(current_state, new_state, **kwargs):
        """
        Processing switch.
        """
        line = kwargs['line']
        parser = kwargs['parser']
        if new_state == 'INIT':
            return parser._process_init(line)
        elif new_state == 'TAG':
            return parser._process_tag(line)
        elif new_state == 'DIR':
            return parser._process_dir(line)
        elif new_state == 'SEC':
            return parser._process_sec(line)
        else:
            return False


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
        'name':    r'Name:\s*([\w\-\s\.\%\?\{\}]+)',
        'version': r'Version:\s*([\w\-\s\.\%\?\{\}]+)',
        'release': r'Release:\s*([\w\-\s\.\%\?\{\}]+)',
        'url':     r'URL:\s*([\w\-\s\.\%\?\{\}\/\:]+)',
        'license': r'License:\s*([\w\-\s\.\+]+)',
        'sources':  r'Source\d*:\s*([\:\/\w\-\s\.\%\?\{\}]+)',
        'patches':   r'Patch\d*:\s*([\:\w\-\s\.\%\?\{\}]+)',

        'buildarch':      r'BuildArch:\s*(\w+)',
        'buildroot':      r'BuildRoot:\s*([\w\s\-\.\/\%\?\{\}\(\)]+)',
        'buildrequires':  r'BuildRequires:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
        'buildconflicts': r'BuildConflicts:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
        'excludearch':    r'ExcludeArch:\s*(\w+)',
        'exclusivearch':  r'ExclusiveArch:\s*(\w+)',
    }

    TAG_REGEXPS = {
        'summary': r'Summary:\s*([^#]+)',
        'group':   r'Group:\s*([\w\s\/]+)',

        'requires':       r'Requires:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
        'provides':       r'Provides:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
        'conflicts':      r'Conflicts:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
        'obsoletes':      r'Obsoletes:\s*([\w\s\-\=\>\<\.\%\?\{\}]+)',
    }

    MACHINE = FiniteMachine(
                State(name='INIT',
                      help_text='Initial defines',
                      next_states=['TAG', 'EOF'],
                      check_perms=[_transition]),
                State(name='TAG',
                      help_text='Tag processing',
                      next_states=['DIR', 'SEC', 'EOF'],
                      check_perms=[_transition]),
                State(name='DIR',
                      help_text='Directive processing',
                      next_states=['TAG', 'SEC', 'EOF'],
                      check_perms=[_transition]),
                State(name='SEC',
                      help_text='Section and scriplet processing',
                      next_states=['TAG', 'DIR', 'EOF'],
                      check_perms=[_transition]),
                State(name='EOF',
                      help_text='End of file',
                      next_states=[],
                      check_perms=[_transition]))

    def __init__(self):
        comm = self.COM_REGEXPS.get('comment', r'(\#.*)')
        self._main_tags = {key: re.compile(r'^\s*%s%s?$' % (exp, comm))
                           for key, exp in self.MAIN_TAG_REGEXPS.iteritems()}
        self._tags = {key: re.compile(r'^\s*%s%s?$' % (exp, comm))
                      for key, exp in self.TAG_REGEXPS.iteritems()}
        self._other = {key: re.compile(r'^\s*%s' % exp)
                       for key, exp in self.COM_REGEXPS.iteritems()}
        self._machine = copy(self.MACHINE)
        self._machine.set_state('INIT')
        self._block = None

    def _process_init(self, line):
        """
        Process initial defines, globals, scl macros. etc. Returns True if the
        processing was successful, otherwise returns False.
        """
        #pdb.set_trace()
        match = self._other['define'].search(line)
        if match:
            key = match.group(2)
            value = match.group(3)
            self._result.setdefault('defines', {})[key] = value
            return True
        if self._other['scl'].search(line) or \
           self._other['condition'].search(line):
            return True
        return False

    def _process_tag(self, line):
        """
        Process all tags. Returns True if the processing was successful,
        otherwise returns False.
        """
        #pdb.set_trace()
        for key, exp in self._main_tags.iteritems():
            #print 'main:', exp.pattern, bool(exp.search(line))
            match = exp.search(line)
            if not match:
                continue

            if key in ('sources', 'patches', 'buildrequires', 'buildconflicts'):
                self._result.setdefault(key, []).append(match.group(1).strip())
            else:
                self._result[key] = match.group(1).strip()
            return True

        for key, exp in self._tags.iteritems():
            #print 'sub:', exp.pattern, bool(exp.search(line))
            match = exp.search(line)
            if not match:
                continue
            if self._block and self._block.startswith('package:'):
                place = self._result['subpackages'][self._block[8:]]
            else:
                place = self._result
            if key in ('requires', 'provides', 'conflicts', 'obsoletes'):
                place.setdefault(key, []).append(match.group(1).strip())
            else:
                place[key] = match.group(1).strip()
            return True
        return False

    def _process_dir(self, line, process=True):
        """
        Process directives such as %package, %files and description.
        Returns True if the processing was successful, otherwise returns False.
        """
        #pdb.set_trace()
        match = self._other['directive'].search(line)
        if match:
            if not process:
                return True
            self._block = '%s:%s' % (match.group(1), match.group(2))
            if match.group(1) == 'package':
                self._result.setdefault('subpackages', {})[match.group(2)] = {}
            return True

        if not self._block or not process or self._process_sec(line, process=False):
            # don't append this line if it's section or if we are only asking
            # from othe process method or if no block is openned
            return False
        if self._is_comment(line):
            return True

        if self._block.startswith('description:'):
            pkg = self._block[12:]
            if not pkg:
                self._result.setdefault('description', []).append(line)
            else:
                sub_pkg = self._result['subpackages'][pkg]
                sub_pkg.setdefault('description', []).append(line)
            return True
        elif self._block.startswith('files:'):
            pkg = self._block[6:]
            if not pkg:
                self._result.setdefault('files', []).append(line)
            else:
                sub_pkg = self._result['subpackages'][pkg]
                sub_pkg.setdefault('files', []).append(line)
            return True
        return False

    def _process_sec(self, line, process=True):
        """
        Process all sections and scriplets such as %prep, %install, %post, etc.
        Returns True if the processing was successful, otherwise returns False.
        """
        #pdb.set_trace()
        match = self._other['section'].search(line)
        if match:
            if not process:
                return True
            self._block = match.group(1).strip()
            return True

        match = self._other['scriptlet'].search(line)
        if match:
            if not process:
                return True
            if match.group(2):
                sclt = match.group(1).strip()
                self._result.setdefault(sclt, []).append(match.group(3))
                self._block = None
            else:
                self._block = match.group(1).strip()
            return True

        if not process or self._process_dir(line, process=False):
            # don't append this line if it's direction or if we are only asking
            # from othe process method
            return False
        if self._is_comment(line):
            return True

        if self._block in ('prep', 'check', 'build', 'install', 'clean',
                           'changelog', 'pre', 'preun', 'post', 'postun',
                           'pretrans', 'posttrans'):
            self._result.setdefault(self._block, []).append(line)
            return True
        return False

    def _is_comment(self, line):
        if self._other['comment'].search(line):
            return True
        return False

    def parse(self, spec_file, fail_on_unknown=False):
        """
        Parses given spec_file and returns SPECFile object. Parser raises
        UnknownLineError if attribute fail_on_unknown is set to True.
        """
        is_file = hasattr(spec_file, 'readlines')
        _spec, _fname = is_file and (spec_file, spec_file.name) or \
                            (open(spec_file, 'r'), os.path.basename(spec_file))

        self._result = {}
        for line in _spec:
            line = line.rstrip('\n').strip()
            if not line:
                continue
            current = self._machine.get_state()
            next_states = [i[1] for i in
                    self._machine.get_next_states_mapping(append_current=True)]

            transition = False
            for state in next_states:
                if self._machine.change_state(state, parser=self,
                                              line=line.rstrip('\n')):
                    transition = True
                    break
            if not transition and fail_on_unknown and not self._is_comment(line):
                raise UnknownLineError('Cannot parse line: "%s"' % line)
        return SPECFile(_fname, **self._result)
