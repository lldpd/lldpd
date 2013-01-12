# -*- coding: utf-8 -*-
"""
Textlinks plugin
"""
import re
import subprocess
import cgi

from hyde.plugin import Plugin

class IncludeManpagePlugin(Plugin):
    """
    Include the content of a manual page.

    The syntax is:

    [[manpage:path/to/manualpage#gitversion]]
    """
    def __init__(self, site):
        super(IncludeManpagePlugin, self).__init__(site)

    def begin_text_resource(self, resource, text):
        if not resource.uses_template:
            return text

        def replace_content(match):
            path = match.group(1)
            version = resource.meta.latestversion

            # execute git show version:path | MAN_KEEP_FORMATTING=1 man -l -
            git = subprocess.Popen(["git", "show", "%s:%s" % (version, path)], stdout=subprocess.PIPE)
            man = subprocess.Popen(["man", "-l", "-"], stdin=git.stdout, stdout=subprocess.PIPE,
                                   env={"MAN_KEEP_FORMATTING": "1"})
            git.stdout.close()
            output = man.communicate()[0]

            return "<div class='manpage'>%s</div>" % self.man(output)

        link = re.compile(r'\[\[manpage:([^\]]+)\]\]', re.UNICODE|re.MULTILINE)
        text = link.sub(replace_content, text)
        return text

    def man(self, output):
        # Escape HTML sequences
        output = cgi.escape(output)

        # Add <br> for new lines
        output = output.replace("\n", "<br>")

        # Dots
        output = re.sub('\\+\b\\+\bo\bo', '&raquo;', output)

        # Bold/Italic
        output = re.sub('(.)\b\\1', r'<b>\1</b>', output)
        output = re.sub(r'</b><b>', '', output)
        output = re.sub('_\b(.)', r'<u>\1</u>', output)
        output = re.sub(r'\</u\>\<u\>', '', output)

        return output.decode('ascii', errors='replace')
