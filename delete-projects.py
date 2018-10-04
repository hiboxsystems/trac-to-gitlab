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
from requests import HTTPError

reload(sys)
sys.setdefaultencoding('utf-8')

from projects import project_group_name, projects

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
        project = projects[project_name]

        if isinstance(project, dict):
            group_name = project.get('group_name', project_group_name)
        else:
            group_name = project_group_name

        project_slug = '%s%%2F%s' % (group_name, project_name)

        try:
            dest.delete_project(project_slug)
        except HTTPError as e:
            if e.response.status_code == 404:
                # The project does not exist - non-fatal error
                pass
            else:
                raise
