# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8

'''
Copyright © 2018
    Hibox Systems Oy Ab <http://www.hibox.tv>

Creates users in GitLab based on a predefined configuration file. Existing
users are not overwritten, unless configured in migrate.cfg.

Use freely under the term of the GPLv3.
'''

import ConfigParser

default_config = {
    'ssl_verify': 'yes',
    'migrate': 'true',
    'overwrite': 'true',
    'exclude_authors': 'trac',
    'uploads': ''
}

config = ConfigParser.ConfigParser(default_config)
config.read('migrate.cfg')

gitlab_url = config.get('target', 'url')
gitlab_access_token = config.get('target', 'access_token')
dest_ssl_verify = config.getboolean('target', 'ssl_verify')
