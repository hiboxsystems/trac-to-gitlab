# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2013
    Eric van der Vlist <vdv@dyomedea.com>
    Jens Neuhalfen <http://www.neuhalfen.name/>
See license information at the bottom of this file
'''

import json
import requests

# See http://code.activestate.com/recipes/52308-the-simple-but-handy-collector-of-a-bunch-of-named/?in=user-97991
class Bunch(object):
    def __init__(self, **kwds):
        self.__dict__.update(kwds)

    @staticmethod
    def create(dictionary):
        if not dictionary:
            return None
        bunch = Bunch()
        bunch.__dict__ = dictionary
        return bunch

class Issues(Bunch):
    pass

class Notes(Bunch):
    pass

class Milestones(Bunch):
    pass

class Connection(object):
    users = None

    """
    Connection to the gitlab API
    """

    def __init__(self, url, access_token, ssl_verify, opts={}):
        """

        :param url: "https://www.neuhalfen.name/gitlab/api/v4"
        :param access_token: "secretsecretsecret"
        """
        self.url = url
        self.access_token = access_token
        self.verify = ssl_verify
        self.ldap_uid_pattern = opts['ldap_uid_pattern']
        self.default_group = opts['default_group']

    def milestone_by_name(self, project_id, milestone_name):
        milestones = self.get("/projects/:project_id/milestones", project_id=project_id)
        for milestone in milestones:
            if milestone['title'] == milestone_name:
                return milestone

    def get_user_id(self, username):
        # Cache the result, so we don't have to hit the server over and
        # over again. This also has the added benefit that we work around
        # bugs in GitLab also: https://gitlab.com/gitlab-org/gitlab-ce/issues/51736
        if self.users == None:
            self.users = self.get("/users", extra_query_params="per_page=1000")

        for user in self.users:
            if user['username'] == username:
                return user["id"]

    def create_user(self, user):
        modified_user = user.copy()
        modified_user['extern_uid'] = self.ldap_uid_pattern % user['username']

        modified_user.update({
            'skip_confirmation': True,
            'provider': 'ldapmain',

            # Is automatically replaced on next logon.
            'password': 'will-be-replaced'
        })
        result = self.post_json('/users', modified_user)
        user_id = result['id']

        # All users added get added to the default group.
        group_json_object = {
            'user_id': user_id,

            # Developer access. More info> https://docs.gitlab.com/ee/api/members.html#add-a-member-to-a-group-or-project
            'access_level': 40
        }

        self.post_json('/groups/%s/members' % self.default_group, group_json_object)

        if modified_user.get('blocked'):
            self.post_json('/users/:id/block', id=user_id)

        if modified_user.get('extra_emails'):
            for email in modified_user['extra_emails']:
                email_json_object = {
                    'email': email,
                    'skip_confirmation': True
                }

                self.post_json('/users/:id/emails', email_json_object, id=user_id)

        if modified_user.get('ssh_keys'):
            ssh_keys = modified_user['ssh_keys']

            for ssh_key in ssh_keys:
                title = ssh_key['title']
                key = ssh_key['key']

                ssh_key_json_object = {
                    'key': key,
                    'title': title
                }

                self.post_json('/users/:id/keys', ssh_key_json_object, id=user_id)

    def delete_user(self, user_id):
        try:
            self.delete('/users/' + str(user_id))
        finally:
            matching_user = None
            for user in self.users:
                if user['id'] == user_id:
                    matching_user = user

            if matching_user != None:
                self.users.remove(matching_user)

    def project_by_name(self, project_name):
        projects = self.get("/projects")
        for project in projects:
            if project['path_with_namespace'] == project_name:
                return project

    def delete(self, url_postfix):
        self._delete(url_postfix)

    def _delete(self, url_postfix):
        completed_url = self._complete_url(url_postfix)
        r = requests.delete(completed_url, verify=self.verify)
        r.raise_for_status()

        return r

    def get(self, url_postfix, extra_query_params="", **keywords):
            return self._get(url_postfix, keywords, extra_query_params)

    def _get(self, url_postfix, keywords, extra_query_params):
        """
        :param url_postfix: e.g. "/projects/:id/issues"
        :param keywords:  map, e.g. { "id" : 5 }
        :return: json of GET
        """
        completed_url = self._complete_url(url_postfix, keywords, extra_query_params)
        r = requests.get(completed_url, verify=self.verify)

        try:
            r.raise_for_status()

            json = r.json()
            return json
        except:
            print r.text
            raise

    def put(self, url_postfix, data, **keywords):
        completed_url = self._complete_url(url_postfix, keywords)
        r = requests.put(completed_url, data= data, verify=self.verify)
        j = r.json()
        return j

    def put_json(self, url_postfix, data, **keywords):
        completed_url = self._complete_url(url_postfix, keywords)
        payload = json.dumps(data)
        r = requests.put(completed_url, data= payload, verify=self.verify)
        j = r.json()
        return j

    def post_json(self, url_postfix, data={}, **keywords):
        completed_url = self._complete_url(url_postfix, keywords)
        payload = json.dumps(data)
        r = requests.post(completed_url, data=data, verify=self.verify)

        try:
            r.raise_for_status()
            j = r.json()
            return j
        except:
            print r.text
            raise

    def create_issue(self, dest_project_id, new_issue):
        if hasattr(new_issue, 'milestone'):
            new_issue.milestone_id = new_issue.milestone
        if hasattr(new_issue, 'assignee'):
            new_issue.assignee_id = new_issue.assignee
        new_ticket = self.post_json("/projects/:id/issues", new_issue.__dict__, id=dest_project_id)
        new_ticket_id  = new_ticket["id"]

        # setting closed in create does not work -- limitation in gitlab
        if new_issue.state == 'closed': self.close_issue(dest_project_id,new_ticket_id)

        return Issues.create(new_ticket)

    def create_milestone(self, dest_project_id, new_milestone):
        if hasattr(new_milestone, 'due_date'):
            new_milestone.due_date = new_milestone.due_date.isoformat()
        existing = Milestones.create(self.milestone_by_name(dest_project_id, new_milestone.title))
        if existing:
            new_milestone.id = existing.id
            return Milestones.create(self.put("/projects/:id/milestones/:milestone_id", new_milestone.__dict__, id=dest_project_id, milestone_id=existing.id))
        else:
            return Milestones.create(self.post_json("/projects/:id/milestones", new_milestone.__dict__, id=dest_project_id))

    def comment_issue(self ,project_id, ticket, note, binary_attachment):
        new_note_data = {
            "id" : project_id,
            "issue_id" :ticket.id,
            "body" : note.note
        }
        self.post_json( "/projects/:project_id/issues/:issue_id/notes", new_note_data, project_id=project_id, issue_id=ticket.id)


    def close_issue(self,project_id,ticket_id):
        new_note_data = {"state_event": "close"}
        self.put("/projects/:project_id/issues/:issue_id", new_note_data, project_id=project_id, issue_id=ticket_id)

    def _complete_url(self, url_postfix, keywords={}, extra_query_params=""):
        url_postfix_with_params = self._url_postfix_with_params(url_postfix, keywords)
        complete_url = "%s%s?private_token=%s&%s" % (self.url, url_postfix_with_params, self.access_token, extra_query_params)
        return complete_url

    def _url_postfix_with_params(self, url_postfix, keywords):
        """

        :param url_postfix:  "/projects/:id/issues"
        :param keywords:  map, e.g. { "id" : 5 }
        :return:  "/projects/5/issues"
        """

        result = url_postfix
        for key, value in keywords.items():
            k = ":" + str(key)
            v = str(value)
            result = result.replace(k, v)
        return result

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
