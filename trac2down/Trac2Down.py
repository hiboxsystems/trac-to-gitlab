# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2013, 2018
    Eric van der Vlist <vdv@dyomedea.com>
    Shigeru KANEMOTO <support@switch-science.com>
    Hibox Systems Oy Ab <http://www.hibox.tv>

See license information at the bottom of this file
'''

from __future__ import division
import datetime
import re
import os
from io import open

# Config Start
meta_header = False              # whether to include the wiki pages' meta data at the top of the markdown
markdown_extension = 'md' # file extension to use for the generated markdown files
# Config End


def convert(text, base_path, wiki_upload_prefix=None, multilines=True):
    text = re.sub('\r\n', '\n', text)
    text = re.sub(r'{{{(.*?)}}}', r'`\1`', text)
    text = re.sub(r'(?sm){{{(\n?#![^\n]+)?\n(.*?)\n(  )?}}}', r'```\n\2\n```', text)

    text = text.replace('[[TOC]]', '')
    text = text.replace('[[BR]]', '\n')
    text = text.replace('[[br]]', '\n')

    text = re.sub(r'\[\[PageOutline.+?\]\]', '\n[[_TOC_]]', text)

    if multilines:
        text = re.sub(r'^\S[^\n]+([^=-_|])\n([^\s`*0-9#=->-_|])', r'\1 \2', text)

    text = re.sub(r'(?m)^======\s+(.*?)\s+======[ ]*$', r'###### \1', text)
    text = re.sub(r'(?m)^=====\s+(.*?)\s+=====[ ]*$', r'##### \1', text)
    text = re.sub(r'(?m)^====\s+(.*?)\s+====[ ]*$', r'#### \1', text)
    text = re.sub(r'(?m)^===\s+(.*?)\s+===[ ]*$', r'### \1', text)
    text = re.sub(r'(?m)^==\s+(.*?)\s+==[ ]*$', r'## \1', text)
    text = re.sub(r'(?m)^=\s+(.*?)\s+=[ ]*$', r'# \1', text)
    text = re.sub(r'^             * ', r'****', text)
    text = re.sub(r'^         * ', r'***', text)
    text = re.sub(r'^     * ', r'**', text)
    text = re.sub(r'^ * ', r'*', text)
    text = re.sub(r'^ \d+. ', r'1.', text)
    text = re.sub(r'\^(.+)\^', r'<sup>\1</sup>', text)
    text = re.sub(r',,(.+),,', r'<sub>\1</sub>', text)

    a = []
    is_table = False
    for line in text.split('\n'):
        is_preformatted = re.match(r'    (-|\*)', line)

        if not is_preformatted:
            line = re.sub(r'\[(https?://[^\s\[\]]+)\s([^\[\]]+)\]', r'[\2](\1)', line)
            line = re.sub(r'\[wiki:([^\s\[\]]+)\s([^\[\]]+)\]', r'[\2](%s/\1)' % os.path.relpath('/wikis/', base_path), line)
            line = re.sub(r'\[wiki:([^\s\[\]]+)\]', r'[\1](\1)', line)
            line = re.sub(r'\[source:([^\s\[\]]+)\s([^\[\]]+)\]', r'[\2](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)
            line = re.sub(r'source:([\S]+)', r'[\1](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)
            line = re.sub(r'\!(([A-Z][a-z0-9]+){2,})', r'\1', line)
            line = re.sub(r'\[\[Image\(source:([^(]+)\)\]\]', r'![](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)

            if wiki_upload_prefix:
                line = re.sub(r'\[\[Image\(wiki:([^\s\[\]]+):([^\s\[\]]+)\)\]\]', r'![\2](%s/\2)' % wiki_upload_prefix, line)

            line = re.sub(r'\[\[Image\(([^(]+)\)\]\]', r'![\1](/uploads/migrated/\1)', line)

            line = re.sub(r"'''\s*(.*?)\s*'''", r'**\1**', line)
            line = re.sub(r"''\s*(.*?)\s*''", r'_\1_', line)

            # FIXME: Unsure about this part. Let's disable it and see what
            # the issues look like without it. Is the issue and wiki formatting
            # different in Trac?
            #is_bulletpoint_list_row = re.match(r'\S*(-|\*)', line)

            #if not is_bulletpoint_list_row and len(line) > 0:
            # Line endings in Wiki format are to be preserved in the GitLab format.
            #line = re.sub(r'$', r'  ', line)
            line = re.sub(r'\\\\$', r'  ', line)

            if line.startswith('||'):
                if not is_table:
                    sep = re.sub(r'[^|]', r'-', line)
                    line = line + '\n' + sep
                    is_table = True
                line = re.sub(r'\|\|', r'|', line)
            else:
                is_table = False
        else:
            is_table = False
        a.append(line)
    text = '\n'.join(a)
    return text


def save_file(text, name, version, date, author, directory):
    folders = name.rsplit("/", 1)
    if len(folders) > 1 and not os.path.exists("%s%s" % (directory, folders[0])):
        os.makedirs("%s%s" % (directory, folders[0]))
    fp = open('%s%s.%s' % (directory, name, markdown_extension), 'w')
    if meta_header:
        fp.write(u'<!-- Name: %s -->' % name)
        fp.write(u'<!-- Version: %d -->' % version)
        fp.write(u'<!-- Last-Modified: %s -->' % date)
        fp.write(u'<!-- Author: %s -->' % author)
    fp.write(unicode(text))
    fp.close()


if __name__ == "__main__":
    SQL = '''
    select
            name, version, time, author, text
        from
            wiki w
        where
            version = (select max(version) from wiki where name = w.name)
'''

    import sqlite3

    conn = sqlite3.connect('../trac.db')
    result = conn.execute(SQL)
    for row in result:
        name = row[0]
        version = row[1]
        time = row[2]
        author = row[3]
        text = row[4]
        text = convert(text, '/wikis/')
        try:
            time = datetime.datetime.fromtimestamp(time).strftime('%Y/%m/%d %H:%M:%S')
        except ValueError:
            time = datetime.datetime.fromtimestamp(time / 1000000).strftime('%Y/%m/%d %H:%M:%S')
        save_file(text, name, version, time, author, 'wiki/')

'''
This file is part of <https://gitlab.dyomedea.com/vdv/trac-to-gitlab>.

This software is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this library. If not, see <http://www.gnu.org/licenses/>.
'''
