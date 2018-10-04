# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2013, 2018
    Eric van der Vlist <vdv@dyomedea.com>
    Shigeru KANEMOTO <support@switch-science.com>
    Hibox Systems Oy Ab <http://www.hibox.tv>

Use freely under the term of the GPLv3.
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


def convert(text, base_path, wiki_upload_prefix=None, issue_upload_prefix=None, multilines=True):
    text = re.sub('\r\n', '\n', text)

    # Single-line preformatted text/code block.
    text = re.sub(r'{{{(.*?)}}}', r'`\1`', text)

    # Multi-line performatted text/fenced code blocks.
    text = re.sub(r'(?sm){{{\s*(\n?#![^\n]+)?\n(.*?)\n([ ]*)}}}', r'```\n\2\n\3```', text)

    text = text.replace('[[TOC]]', '')
    text = text.replace('[[BR]]\n', '  \n')
    text = text.replace('[[br]]\n', '  \n')
    text = text.replace('[[BR]]', '\n')
    text = text.replace('[[br]]', '\n')

    text = re.sub(r'\[\[PageOutline.*?\]\]', '\n[[_TOC_]]', text)

    # Handle headings of various levels. The (#.+)? optional part is something that can be used
    # to give headings a particular anchor name => not supported in Markdown, so dropped in the
    # converted content.
    text = re.sub(r'(?m)^======\s+(.*?)(\s+======[ ]*)?$', r'###### \1', text)
    text = re.sub(r'(?m)^=====\s+(.*?)(\s+=====[ ]*)?$', r'##### \1', text)
    text = re.sub(r'(?m)^====\s+(.*?)(\s+====[ ]*)?$', r'#### \1', text)
    text = re.sub(r'(?m)^===\s+(.*?)(\s+===[ ]*)?(#.+)?$', r'### \1', text)
    text = re.sub(r'(?m)^==\s+(.*?)(\s+==[ ]*)?(#.+)?$', r'## \1', text)
    text = re.sub(r'(?m)^=\s+(.*?)(\s+=[ ]*)?$', r'# \1', text)
    text = re.sub(r'^             * ', r'****', text)
    text = re.sub(r'^         * ', r'***', text)
    text = re.sub(r'^     * ', r'**', text)

    # Bulletpoint, intended one level. These are often used after numbered lists, and to get them to
    # be properly rendered in Markdown we need to indent them at least four spaces.
    text = re.sub(r'(?m)^  -', r'     -', text)

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
            line = re.sub(r'\[wiki:([^\s\[\]]+)\]', r'[\1](%s/\1)' % os.path.relpath('/wikis/', base_path), line)
            line = re.sub(r'\[source:([^\s\[\]]+)\s([^\[\]]+)\]', r'[\2](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)
            line = re.sub(r'source:([\S]+)', r'[\1](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)
            line = re.sub(r'\!(([A-Z][a-z0-9]+){2,})', r'\1', line)
            line = re.sub(r'\[\[Image\(source:([^(]+)\)\]\]', r'![](%s/\1)' % os.path.relpath('/tree/master/', base_path), line)

            if wiki_upload_prefix:
                line = re.sub(r'\[\[Image\(wiki:([^\s\[\]]+):([^\s\[\]]+)\)\]\]', r'![\2](%s/\2)' % wiki_upload_prefix, line)
                line = re.sub(r'\[\[Image\(([^(]+)\)\]\]', r'![\1](%s/\1)' % wiki_upload_prefix, line)
            elif issue_upload_prefix:
                if re.search(r'\[\Image\(wiki:.+?\)]', line):
                    raise Exception('[Image(wiki:foo)] tag encountered in non-wiki content. This is not supported.')

                line = re.sub(r'\[\[Image\(([^(]+)\)\]\]', r'![\1](%s/\1)' % issue_upload_prefix, line)
            else:
                if re.search(r'\[\Image\(.+?\)]', line):
                    raise Exception('[Image(foo)] tags are not supported when neither wiki_upload_prefix nor issue_upload_prefix is set')

            # Bold text
            line = re.sub(r"'''\s*(.*?)\s*'''", r'**\1**', line)

            # Italic text
            line = re.sub(r"''\s*(.*?)\s*''", r'_\1_', line)

            # Line endings in Wiki format are to be preserved in the GitLab format.
            line = re.sub(r'\\\\$', r'  ', line)

            if line.startswith('||'):
                if not is_table:
                    sep = re.sub(r'[^|]', r'-', line)

                    # Prepending with a newline is important, since tables that are "glued together"
                    # with text right above it will not be rendered correctly in GitLab Markdown.
                    line = '\n' + line + '\n' + sep
                    is_table = True

                # Sometimes, table cells are separated by |||| instead of || in our wiki content.
                line = re.sub(r'\|\|\|\|', r'|', line)
                line = re.sub(r'\|\|', r'|', line)

                # Special quirk to deal with tables without headers.
                line = re.sub(r'=\s+=', '', line)

                # = foo = syntax is used to center table headings in Trac wiki format. The same can be done in GitLab markdown,
                # but it involves modifying the line afterwards. We KISS and drop the formatting in this case, sacrificing
                # correctness for keeping the conversion code simpler.
                line = re.sub(r'=\s*(.*?)\s*=', r'\1', line)
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
