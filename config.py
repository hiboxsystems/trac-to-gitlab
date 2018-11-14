# -*- coding: utf-8 -*-

'''
Copyright © 2018
    Hibox Systems Oy Ab <http://www.hibox.tv>

Use freely under the term of the GPLv3.
'''

import ConfigParser
import ast
import codecs

# Not used by us, but re-exported for our clients.
from migrate_config import \
    component_translation_map, \
    keywords_map, \
    label_colors, \
    label_prefix_translation_map, \
    milestone_map

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
