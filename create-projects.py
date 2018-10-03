#!/usr/bin/env python
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2018
    Hibox Systems Oy Ab <http://www.hibox.tv>

Creates projects in GitLab based on a predefined configuration file. Before creating the projects, they are deleted if they exist.

Use freely under the term of the GPLv3.
'''

import ConfigParser
import sys
from gitlab_api import Connection

reload(sys)
sys.setdefaultencoding('utf-8')

from projects import project_group_id, projects

default_config = {
    'ssl_verify': 'yes',
    'overwrite' : 'true'
}

config = ConfigParser.ConfigParser(default_config)
config.read('migrate.cfg')

gitlab_url = config.get('target', 'url')
gitlab_access_token = config.get('target', 'access_token')
dest_ssl_verify = config.getboolean('target', 'ssl_verify')

if __name__ == "__main__":
    opts = {
    }
    dest = Connection(gitlab_url, gitlab_access_token, dest_ssl_verify, opts)

    for project_name in projects:
        import_url = projects[project_name]
        project = {
            'import_url': import_url,
            'name': project_name,
            'path': project_name,
            'jobs_enabled': False,
            'namespace_id': project_group_id
        }

        dest.create_project(project)
