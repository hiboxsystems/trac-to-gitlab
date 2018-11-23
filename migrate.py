#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright © 2013, 2018
    Eric van der Vlist <vdv@dyomedea.com>
    Jens Neuhalfen <http://www.neuhalfen.name/>
    Hibox Systems Oy Ab <http://www.hibox.tv>

Use freely under the term of the GPLv3.
'''

from __future__ import unicode_literals
import argparse
import re
import os
import config as config_reader
import ast
from datetime import datetime
import xmlrpclib
import trac2down
import sys


"""
What
=====

 This script migrates Trac tickets to GitLab issues, and Trac wiki pages to
 GitLab wiki pages.

License
========

 License: GPLv3

Requirements
==============

 * Python 2, xmlrpclib, requests
 * Trac with xmlrpc plugin enabled
 * Peewee (direct method)
 * GitLab

"""

try:
    # Python 3
    from collections.abc import MutableSet
except ImportError:
    # Python 2
    from collections import MutableSet

class CasePreservingSet(MutableSet):
    def __init__(self, *values):
        self._values = {}
        for v in values:
            self.add(v)

    def __repr__(self):
        return '<{} at {:x}>'.format(
           tuple(self._values.values()), id(self)
        )

    def __contains__(self, value):
        return value.lower() in self._values

    def __iter__(self):
        try:
            # Python 2
            return self._values.itervalues()
        except AttributeError:
            # Python 3
            return iter(self._values.values())

    def __len__(self):
        return len(self._values)

    def add(self, value):
        self._values[value.lower()] = value

    def discard(self, value):
        try:
            del self._values[value.lower()]
        except KeyError:
            pass

config = config_reader.config
component_translation_map = config_reader.component_translation_map
keywords_map = config_reader.keywords_map
label_colors = config_reader.label_colors
label_prefix_translation_map = config_reader.label_prefix_translation_map
milestone_map = config_reader.milestone_map

trac_url = config.get('source', 'url')
dest_project_name = config.get('target', 'project_name')
uploads_path = config.get('target', 'uploads')
default_group = config.get('target', 'default_group')
method = config.get('target', 'method')

from projects import get_dest_project_id_for_issue, get_dest_project_ids, issue_mutator

if method == 'api':
    # TODO: consider dropping this, since we never test it and it doesn't
    # support all functionality.
    from gitlab_api import Connection, Issues, IssueAssignees, Notes, Milestones

    print("importing api")
    gitlab_url = config.get('target', 'url')
    gitlab_access_token = config.get('target', 'access_token')
    dest_ssl_verify = config.getboolean('target', 'ssl_verify')
    overwrite = False
elif method == 'direct':
    print("importing direct")
    from gitlab_direct import Connection, Issues, IssueAssignees, Notes, Milestones

    db_name = config.get('target', 'db-name')
    db_password = config.get('target', 'db-password')
    db_user = config.get('target', 'db-user')
    db_path = config.get('target', 'db-path')
    overwrite = config.getboolean('target', 'overwrite')

users_map = ast.literal_eval(config.get('target', 'usernames'))

default_user = None
if config.has_option('target', 'default_user'):
    default_user = config.get('target', 'default_user')

only_issues = None
if config.has_option('issues', 'only_issues'):
    only_issues = ast.literal_eval(config.get('issues', 'only_issues'))

parser = argparse.ArgumentParser()
parser.add_argument('--no-convert-milestones',
                    help="disable conversion of all milestones (enabled by default)",
                    action="store_true")
parser.add_argument('--issues',
                    help="migrate issues (default: false)",
                    action="store_true")
parser.add_argument("--only-issue",
                    help="migrate one or more specific issues instead of all. Separate multiple issues with a comma: 123,456,789 or ranges: 123-456")
parser.add_argument('--wiki',
                    help="migrate wiki pages (default: false)",
                    action="store_true")
parser.add_argument('--ignore-wiki-attachments',
                    help="ignore wiki attached files (default: false)",
                    action="store_true")
parser.add_argument("--wiki-page",
                    help="migrate a specific wiki page instead of the whole wiki. Implies --wiki.")
args = parser.parse_args()

convert_milestones = True
if args.no_convert_milestones:
    convert_milestones = False

must_convert_issues = False
must_convert_wiki = False
if args.issues:
    must_convert_issues = True

if args.only_issue:
    must_convert_issues = True
    convert_milestones = False

    if ',' in args.only_issue:
        only_issues = map(int, args.only_issue.split(','))
    elif '-' in args.only_issue:
        start, end = args.only_issue.split('-')

        # The +1 is needed to get 6000-7000 to behave as the user would expect, i.e. include issue number 7000 also.
        only_issues = range(int(start), int(end) + 1)
    else:
        only_issues = [int(args.only_issue)]

if args.wiki:
    must_convert_wiki = True

ignore_wiki_attachments = False
if args.ignore_wiki_attachments:
    ignore_wiki_attachments = True

wiki_override_page = None
if args.wiki_page:
    wiki_override_page = args.wiki_page
    must_convert_wiki = True

delete_existing_issues = True
if config.has_option('issues', 'delete_existing_issues'):
    delete_existing_issues = config.getboolean('issues', 'delete_existing_issues')

pattern_changeset = r'(?sm)In \[changeset:"([^"/]+?)(?:/[^"]+)?"\]:\n\{\{\{(\n#![^\n]+)?\n(.*?)\n\}\}\}'
matcher_changeset = re.compile(pattern_changeset)

pattern_changeset2 = r'\[changeset:([a-zA-Z0-9]+)\]'
matcher_changeset2 = re.compile(pattern_changeset2)


def convert_xmlrpc_datetime(dt):
    return datetime.strptime(str(dt), "%Y%m%dT%H:%M:%S")


def format_changeset_comment(m):
    return 'In changeset ' + m.group(1) + ':\n> ' + m.group(3).replace('\n', '\n> ')


def fix_wiki_syntax(markup):
    markup = matcher_changeset.sub(format_changeset_comment, markup)
    markup = matcher_changeset2.sub(r'\1', markup)
    return markup


def get_dest_milestone_id(dest, dest_project_id, milestone_name):
    dest_milestone_id = dest.milestone_by_name(dest_project_id, milestone_name)
    if not dest_milestone_id:
        raise ValueError("Milestone '%s' of project '%s' not found" % (milestone_name, dest_project_name))
    return dest_milestone_id["id"]


def translate_component(component):
    return component_translation_map.get(component, component)


def translate_keyword(keyword):
    return keywords_map.get(keyword, keyword)


def translate_milestone(milestone):
    result = milestone_map.get(milestone, [])
    return result or []


def convert_issues(source, dest, dest_project_ids, convert_milestones, only_issues=None,
                   get_dest_project_id_for_issue=None, issue_mutator=None):
    if only_issues is None: only_issues = []

    if overwrite and method == 'direct':
        for project_id in dest_project_ids:
            dest.clear_issues(project_id, only_issues)

    milestone_map_id = {}
    if convert_milestones:
        for dest_project_id in dest_project_ids:
            for milestone_name in source.ticket.milestone.getAll():
                milestone = source.ticket.milestone.get(milestone_name)
                print("migrated milestone: %s" % milestone_name)
                new_milestone = Milestones(
                    description=trac2down.convert(fix_wiki_syntax(milestone['description']), '/milestones/', False),
                    title=milestone['name'],
                    state='active' if str(milestone['completed']) == '0' else 'closed'
                )
                if method == 'direct':
                    new_milestone.project = dest_project_id
                if milestone['due']:
                    new_milestone.due_date = convert_xmlrpc_datetime(milestone['due'])
                new_milestone = dest.create_milestone(dest_project_id, new_milestone)
                milestone_map_id[milestone_name] = new_milestone.id

    get_all_tickets = xmlrpclib.MultiCall(source)

    gitlab_user_cache = {}

    if only_issues:
        print("getting tickets from trac: %s" % only_issues)
        for ticket in only_issues:
            get_all_tickets.ticket.get(ticket)
    else:
        print("getting all tickets from trac")
        for ticket in source.ticket.query("max=0&order=id"):
            get_all_tickets.ticket.get(ticket)

    image_regexp = re.compile(r'\.(jpg|jpeg|png|gif)$')
    title_label_regexp = re.compile(r'(\[.+?\]|.+?:)')

    for src_ticket in get_all_tickets():
        src_ticket_id = src_ticket[0]

        if only_issues and src_ticket_id not in only_issues:
            print("SKIP unwanted ticket #%s" % src_ticket_id)
            continue

        print 'migrating ticket %d' % src_ticket_id

        src_ticket_data = src_ticket[3]

        src_ticket_billable = src_ticket_data.get('billable', '0')
        src_ticket_component = src_ticket_data['component']
        src_ticket_keywords = re.split(r'[, ]', src_ticket_data['keywords'])
        src_ticket_milestone = src_ticket_data['milestone']
        src_ticket_priority = src_ticket_data['priority']
        src_ticket_resolution = src_ticket_data['resolution']
        src_ticket_status = src_ticket_data['status']
        src_ticket_version = src_ticket_data['version']

        new_labels = CasePreservingSet()

        if src_ticket_billable == '1':
            new_labels.add('billable')

        if src_ticket_milestone:
            for label in translate_milestone(src_ticket_milestone):
                new_labels.add(label)

        if src_ticket_priority == 'high':
            new_labels.add('high priority')
        elif src_ticket_priority == 'medium':
            pass
        elif src_ticket_priority == 'low':
            new_labels.add('low priority')

        if src_ticket_resolution == '':
            # active ticket
            pass
        elif src_ticket_resolution == 'fixed':
            pass
        elif src_ticket_resolution == 'invalid':
            new_labels.add('invalid')
        elif src_ticket_resolution == 'wontfix':
            new_labels.add("won't fix")
        elif src_ticket_resolution == 'duplicate':
            new_labels.add('duplicate')
        elif src_ticket_resolution == 'worksforme':
            new_labels.add('works for me')

        if src_ticket_component != '':
            for component in src_ticket_component.split(','):
                component = component.strip()
                translated_component = translate_component(component)

                if translated_component:
                    new_labels.add(translated_component)
                else:
                    print('    WARN: Dropping component %s' % component)

        for keyword in src_ticket_keywords:
            keyword = keyword.strip()
            if not keyword:
                continue

            translated_keyword = translate_keyword(keyword)

            if translated_keyword:
                new_labels.add(translated_keyword)
            else:
                print('    WARN: Dropping keyword %s' % keyword)

        new_state = 'opened'
        if src_ticket_status == 'new':
            new_state = 'opened'
        elif src_ticket_status == 'assigned':
            new_state = 'opened'
            new_labels.add('Do')
        elif src_ticket_status == 'reopened':
            # There is no 'reopened' state in GitLab.
            new_state = 'opened'
        elif src_ticket_status == 'closed':
            new_state = 'closed'
        elif src_ticket_status == 'accepted':
            new_state = 'opened'
            new_labels.add('Do')
        elif src_ticket_status == 'reviewing' or src_ticket_status == 'testing':
            new_labels.add('Check')
        else:
            print("!!! Unknown ticket status: %s, not preserving in migrated data" % src_ticket_status)

        summary = src_ticket_data['summary']
        sanitized_summary = None
        title_result = title_label_regexp.search(summary)

        if title_result:
            prefix = title_result.group(1)
            lowercased_prefix = prefix.lower()

            # Awkward way, but prefix.translate() works differently on str and unicode objects so
            # this is good enough for now.
            mangled_prefix = lowercased_prefix.replace('[', '').replace(']', '').replace(':', '')
            translated_prefix = label_prefix_translation_map.get(mangled_prefix, '')

            if translated_prefix != '':
                if translated_prefix == None:
                    # None values have a special meaning, indicate: "Remove this prefix, but don't add a label".
                    print('    !!! Dropping prefix %s' % mangled_prefix)
                else:
                    # Prefix found in whitelist.
                    new_labels.add(translated_prefix)

                sanitized_summary = summary[title_result.end():].strip()

        if not sanitized_summary:
            sanitized_summary = summary

        # FIXME: Would like to put these in deeply nested folder structure instead of dashes, but
        # the GitLab uploads route only supports a single subfolder below uploads:
        # https://github.com/gitlabhq/gitlabhq/blob/master/config/routes/uploads.rb#L22-L25
        issue_attachment_path = os.path.join('issue-attachment-%d' % src_ticket_id)

        new_issue = Issues(
            title=sanitized_summary,
            description=trac2down.convert(
                fix_wiki_syntax(src_ticket_data['description']),
                '/issues/',
                False,
                issue_upload_prefix='/uploads/' + issue_attachment_path
            ),
            state=new_state,
            labels=new_labels
        )

        if get_dest_project_id_for_issue:
            dest_project_id = get_dest_project_id_for_issue(dest, new_issue)
        else:
            # No function defined - assume that we have been provided a single project ID.
            dest_project_id = dest_project_ids[0]

        if issue_mutator:
            issue_mutator(new_issue)

        print("    Final set of labels: %s" % ', '.join(new_issue.labels))

        if src_ticket_version:
            if src_ticket_version == 'trunk' or src_ticket_version == 'dev':
                pass
            else:
                release_milestone_name = 'release-%s' % src_ticket_version
                if release_milestone_name not in milestone_map_id:
                    print("    creating new milestone for %s" % release_milestone_name)
                    new_milestone = Milestones(
                        title=release_milestone_name,
                        description='',
                        state='closed'
                    )
                    if method == 'direct':
                        new_milestone.project = dest_project_id
                    new_milestone = dest.create_milestone(dest_project_id, new_milestone)
                    milestone_map_id[release_milestone_name] = new_milestone.id
                new_issue.milestone = milestone_map_id[release_milestone_name]

        # Additional parameters for direct access
        if method == 'direct':
            new_issue.created_at = convert_xmlrpc_datetime(src_ticket[1])
            new_issue.updated_at = convert_xmlrpc_datetime(src_ticket[2])

            new_issue.project = dest_project_id
            new_issue.state = new_state

            try:
                new_issue.author = get_cached_user_id(dest, gitlab_user_cache, users_map[src_ticket_data['reporter']])
            except KeyError:
                if default_user:
                    new_issue.author = get_cached_user_id(dest, gitlab_user_cache, default_user)
                else:
                    raise
            if overwrite:
                new_issue.iid = src_ticket_id
            else:
                new_issue.iid = dest.get_issues_iid(dest_project_id)

        if 'milestone' in src_ticket_data and not new_issue.milestone:
            milestone = src_ticket_data['milestone']
            if milestone and milestone_map_id.get(milestone):
                new_issue.milestone = milestone_map_id[milestone]

        new_ticket = dest.create_issue(dest_project_id, new_issue)

        if src_ticket_data['owner'] != '':
            try:
                mapped_user = users_map[src_ticket_data['owner']]
            except KeyError:
                if default_user:
                    mapped_user = default_user
                else:
                    raise
            assign_query = IssueAssignees.insert(
                issue=new_ticket.id,
                user=get_cached_user_id(dest, gitlab_user_cache, mapped_user)
            )
            dest.assign_issue(assign_query)

        changelog = source.ticket.changeLog(src_ticket_id)
        is_attachment = False

        for change in changelog:
            (change_datetime, change_user, change_type, _, change_text, _) = change

            if change_type == "attachment":
                # The attachment will be described in the next change!
                is_attachment = True
                attachment_file_name = change_text

            if change_type == "comment" and (change_text != '' or is_attachment):
                note = Notes(
                    note=trac2down.convert(
                        fix_wiki_syntax(change_text),
                        '/issues/',
                        False,
                        issue_upload_prefix=issue_attachment_path
                    )
                )
                binary_attachment = None

                if method == 'direct':
                    note.created_at = convert_xmlrpc_datetime(change_datetime)
                    note.updated_at = convert_xmlrpc_datetime(change_datetime)
                    try:
                        user = users_map[change_user]
                        note.author = get_cached_user_id(dest, gitlab_user_cache, user)
                    except KeyError:
                        if default_user:
                            note.author = get_cached_user_id(dest, gitlab_user_cache, default_user)
                        else:
                            raise
                    if is_attachment:
                        # Intermediate save needed to make note.id be populated with the real ID of the record.
                        note.save()

                        note.attachment = '%s/%s' % (issue_attachment_path, attachment_file_name)
                        image_prefix = ''
                        if image_regexp.search(attachment_file_name):
                            image_prefix = '!'

                        attachment_label = note.note
                        if not attachment_label:
                            attachment_label = attachment_file_name

                        note.note = '%s[%s](/uploads/%s)' % (image_prefix, attachment_label, note.attachment)

                        print("    migrating attachment for ticket id %s: %s" % (src_ticket_id, attachment_file_name))
                        binary_attachment = source.ticket.getAttachment(src_ticket_id,
                                                                        attachment_file_name.encode('utf8')).data

                dest.comment_issue(dest_project_id, new_ticket, note, binary_attachment)
                is_attachment = False


def convert_wiki(source, dest):
    exclude_authors = [a.strip() for a in config.get('wiki', 'exclude_authors').split(',')]
    target_directory = config.get('wiki', 'target-directory')

    if wiki_override_page:
        pages = [wiki_override_page]
    else:
        pages = source.wiki.getAllPages()

    i = 0
    for name in pages:
        i += 1
        info = source.wiki.getPageInfo(name)
        if info == 0:
            raise Exception("No page named %s could be found" % name)

        if info['author'] in exclude_authors:
            continue

        page = source.wiki.getPage(name)
        print("[%d/%d] Page %s:%s" % (i, len(pages), name, info))
        if name == 'WikiStart':
            name = 'home'

        sanitized_name = name.replace('/', '-').lower()
        upload_prefix = 'uploads/%s' % sanitized_name
        old_attachment_prefix = '/attachment/wiki/%s' % name
        old_raw_attachment_prefix = '/raw-attachment/wiki/%s' % name
        converted = trac2down.convert(
            page,
            os.path.dirname('/wikis/%s' % name),
            wiki_upload_prefix=upload_prefix,
            old_attachment_prefix=old_attachment_prefix,
            old_raw_attachment_prefix=old_raw_attachment_prefix
        )

        if method == 'direct' and not ignore_wiki_attachments:
            files_not_linked_to = []

            for attachment_filename in source.wiki.listAttachments(name):
                binary_attachment = source.wiki.getAttachment(attachment_filename).data
                attachment_name = attachment_filename.split('/')[-1]
                sanitized_attachment_name = attachment_name \
                    .replace(' ', '_') \
                    .replace('(', '') \
                    .replace(')', '')
                attachment_directory = os.path.join(target_directory, 'uploads', sanitized_name)

                dest.save_wiki_attachment(attachment_directory, sanitized_attachment_name, binary_attachment)
                converted = converted.replace(r'%s/%s)' % (sanitized_name, attachment_filename),
                                                r'%s/%s)' % (sanitized_name, sanitized_attachment_name))
                if '%s/%s)' % (upload_prefix, sanitized_attachment_name) not in converted:
                    files_not_linked_to.append(sanitized_attachment_name)

                print('  ' + sanitized_attachment_name)

            if len(files_not_linked_to) > 0:
                print '  %d non-linked attachments detected, manually adding to generated Markdown' % len(files_not_linked_to)
                converted += '\n\n'
                converted += '##### Attached files:\n'
                for file_name in files_not_linked_to:
                    converted += '- [%s](uploads/%s/%s)\n' % (file_name, sanitized_name, file_name)

        trac2down.save_file(converted, name, info['version'], info['lastModified'], info['author'], target_directory)


def get_cached_user_id(dest, gitlab_user_cache, username):
    if username in gitlab_user_cache:
        return gitlab_user_cache[username]
    else:
        uid = dest.get_user_id(username)
        gitlab_user_cache[username] = uid
        return uid


if __name__ == "__main__":
    if method == 'api':
        dest = Connection(gitlab_url, gitlab_access_token, dest_ssl_verify)
    elif method == 'direct':
        opts = {
            'default_ticket_namespace': default_group,
            'label_colors': label_colors
        }
        dest = Connection(db_name, db_user, db_password, db_path, uploads_path, dest_project_name, opts)

    source = xmlrpclib.ServerProxy(trac_url)

    if get_dest_project_ids:
        # Converting from a source project to multiple target projects, with a defined function
        # to determine which the target project is.
        dest_project_ids = get_dest_project_ids(dest)
    else:
        # Converting from a source project to a single target project.
        dest_project_ids = [dest.project_id_by_name(dest_project_name)]

    if must_convert_issues:
        convert_issues(source, dest, dest_project_ids, convert_milestones, only_issues=only_issues, get_dest_project_id_for_issue=get_dest_project_id_for_issue, issue_mutator=issue_mutator)

    if must_convert_wiki:
        convert_wiki(source, dest)
