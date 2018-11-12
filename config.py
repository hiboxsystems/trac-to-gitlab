# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8

'''
Copyright © 2018
    Hibox Systems Oy Ab <http://www.hibox.tv>

Use freely under the term of the GPLv3.
'''

import ConfigParser
import ast
import codecs

default_config = {
    'ssl_verify': 'yes',
    'migrate': 'true',
    'overwrite': 'true',
    'exclude_authors': 'trac',
    'uploads': ''
}

config = ConfigParser.ConfigParser(default_config)
config.readfp(codecs.open('migrate.cfg', 'r', 'utf8'))

gitlab_url = config.get('target', 'url')
gitlab_access_token = config.get('target', 'access_token')
dest_ssl_verify = config.getboolean('target', 'ssl_verify')

try:
    component_translation_map = ast.literal_eval(config.get('issues', 'component_translation_map'))
except ConfigParser.NoOptionError:
    component_translation_map = {}
