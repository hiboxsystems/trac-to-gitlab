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

trac_url = config.get('source', 'url')
ldap_uid_pattern = config.get('target', 'ldap_uid_pattern')
project_name = config.get('target', 'project_name')

# NB: This script only supports the 'api' method, not direct database
# access.
method = 'api'

gitlab_url = config.get('target', 'url')
gitlab_access_token = config.get('target', 'access_token')
dest_ssl_verify = config.getboolean('target', 'ssl_verify')

from users import users, fork_users, default_groups

if __name__ == "__main__":
    opts = {
        'ldap_uid_pattern': ldap_uid_pattern,
        'default_groups': default_groups
    }
    dest = Connection(gitlab_url, gitlab_access_token, dest_ssl_verify, opts)

    # Create non-existing users
    for user in users:
        gitlab_user = dest.get_user_id(user['username'])

        if gitlab_user == None:
            print("User does not exist in GitLab: %s, creating..." % user['username'])
            dest.create_user(user)

    source = xmlrpclib.ServerProxy(trac_url, encoding = 'UTF-8')

    # Create forks of repositories
    # TODO: Could handle 409 errors which will be raised if the fork already exists.
    for fork_user in fork_users:
        dest.create_fork(fork_user, project_name)
