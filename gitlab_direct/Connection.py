# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8
'''
Copyright © 2013 - 2017
    Eric van der Vlist <vdv@dyomedea.com>
    Jens Neuhalfen <http://www.neuhalfen.name/>
See license information at the bottom of this file
'''


from peewee import PostgresqlDatabase
from .model import *
import os
import shutil
from datetime import datetime
from io import open


class Connection(object):
    """
    Connection to the gitlab database
    """

    def __init__(self, db_name, db_user, db_password, db_path, uploads_path, project_name):
        """
        """
        db = PostgresqlDatabase(db_name, user=db_user, host=db_path)
        database_proxy.initialize(db)
        self.uploads_path = uploads_path
        self.project_name = project_name

    def clear_issues(self, project_id):

        # Delete all custom issue boards.
        print("removing issue boards")
        for list in Lists.select():
            list.delete_instance()

        # Delete all the uses of the labels of the project.
        print("removing labels")
        for label in Labels.select():
            LabelLinks.delete().where( LabelLinks.label == label.id ).execute()
            ## You probably do not want to delete the labels themselves, otherwise you'd need to
            ## set their colour every time when you re-run the migration.
            #label.delete_instance()

        # Delete issues and everything that goes with them...
        print("removing issues")
        for issue in Issues.select().where(Issues.project == project_id):
            for note in Notes.select().where( (Notes.project == project_id) & (Notes.noteable_type == 'Issue') & (Notes.noteable == issue.id)):
                if note.attachment != None:
                    directory = os.path.join(self.uploads_path, 'note/attachment/%s' % note.id)
                    try:
                        shutil.rmtree(directory)
                    except:
                        pass
                Events.delete().where( (Events.project == project_id) & (Events.target_type == 'Note' ) & (Events.target == note.id) ).execute()
                note.delete_instance()

            Events.delete().where( (Events.project == project_id) & (Events.target_type == 'Issue' ) & (Events.target == issue.id) ).execute()
            issue.delete_instance()

        print("removing milestones")
        Milestones.delete().where( Milestones.project == project_id ).execute()

    def milestone_by_name(self, project_id, milestone_name):
        for milestone in Milestones.select().where((Milestones.title == milestone_name) & (Milestones.project == project_id)):
            return milestone._data
        return None

    def project_by_name(self, project_name):
        (namespace, name) = project_name.split('/')
        print(name)
        for project in Projects.select().join(Namespaces, on=(Projects.namespace == Namespaces.id )).where((Projects.path == name) & (Namespaces.path == namespace)):
            print(project._data)
            return project._data
        return None

    def get_user(self, username):
        return Users.get(Users.username == username)

    def get_user_id(self, username):
        return self.get_user(username).id

    def get_issues_iid(self, dest_project_id):
        return Issues.select().where(Issues.project == dest_project_id).aggregate(fn.Count(Issues.id)) + 1

    def create_milestone(self, dest_project_id, new_milestone):
        try:
            existing = Milestones.get((Milestones.title == new_milestone.title) & (Milestones.project == dest_project_id))
            for k in new_milestone._data:
                if k not in ('id', 'iid'):
                    existing._data[k] = new_milestone._data[k]
            new_milestone = existing
        except:
            new_milestone.iid = Milestones.select().where(Milestones.project == dest_project_id).aggregate(fn.Count(Milestones.id)) + 1
            new_milestone.created_at = datetime.now()
            new_milestone.updated_at = datetime.now()
        new_milestone.save()
        return new_milestone

    def create_issue(self, dest_project_id, new_issue):
        new_issue.save()
        event = Events.create(
            action=1,
            author=new_issue.author,
            created_at=new_issue.created_at,
            project=dest_project_id,
            target=new_issue.id,
            target_type='Issue',
            updated_at=new_issue.created_at
        )
        event.save()
        for title in set(new_issue.labels.split(',')):
            try:
                label = Labels.get(Labels.title == title)
            except:
                label = Labels.create(
                    title=title,
                    color='#0000FF',
                    group=5,
                    type='GroupLabel',
                    created_at=new_issue.created_at,
                    update_at=new_issue.created_at
                )
                label.save()
            label_link = LabelLinks.create(
                label=label.id,
                target=new_issue.id,
                target_type='Issue',
                created_at=new_issue.created_at,
                update_at=new_issue.created_at
            )
            label_link.save()
        return new_issue

    def assign_issue(self, new_issue_assignment):
        new_issue_assignment.save()

    def comment_issue(self, project_id, ticket, note, binary_attachment):
        note.project = project_id
        note.noteable = ticket.id
        note.noteable_type = 'Issue'
        note.save()

        if binary_attachment:
            directory = os.path.join(self.uploads_path, 'note/attachment/%s' % note.id)
            if not os.path.exists(directory):
                os.makedirs(directory)
            path = os.path.join(directory, note.attachment)
            f = open(path, "wb")
            f.write(binary_attachment)
            f.close()

        event = Events.create(
            action=1,
            author=note.author,
            created_at=note.created_at,
            project=project_id,
            target=note.id,
            target_type='Note',
            updated_at=note.created_at
        )
        event.save()

    def save_wiki_attachment(self, path, binary):
        full_path = os.path.join(self.uploads_path, self.project_name, 'migrated', path)
        if os.path.isfile(full_path):
            raise Exception("file already exists: %s" % full_path)
        directory = os.path.dirname(full_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        f = open(full_path, "wb")
        f.write(binary)
        f.close()


'''
This file is part of <https://gitlab.dyomedea.com/vdv/trac-to-gitlab>.

This sotfware is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This sotfware is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library. If not, see <http://www.gnu.org/licenses/>.
'''
