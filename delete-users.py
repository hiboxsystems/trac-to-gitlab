#!/usr/bin/env python
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2018
    Hibox Systems Oy Ab <http://www.hibox.tv>

Creates users in GitLab based on a predefined configuration file. Existing
users are not overwritten, unless configured in migrate.cfg.

Use freely under the term of the GPLv3.
'''

import ConfigParser
import ast
import xmlrpclib
import sys
from gitlab_api import Connection

reload(sys)
sys.setdefaultencoding('utf-8')

default_config = {
    'ssl_verify': 'yes',
    'overwrite' : 'true'
}

config = ConfigParser.ConfigParser(default_config)
config.read('migrate.cfg')

# NB: This script only supports the 'api' method, not direct database
# access.
method = 'api'

gitlab_url = config.get('target', 'url')
gitlab_access_token = config.get('target', 'access_token')
dest_ssl_verify = config.getboolean('target', 'ssl_verify')

from users import users

if __name__ == "__main__":
    opts = {}
    dest = Connection(gitlab_url, gitlab_access_token, dest_ssl_verify, opts)

    for user in users:
        gitlab_user = dest.get_user_id(user['username'])

        if gitlab_user:
            print 'Deleting user %s' % user['username']
            dest.delete_user(gitlab_user)
