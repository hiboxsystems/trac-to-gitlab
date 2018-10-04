#!/usr/bin/env python
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python fileencoding=utf-8

'''
Copyright © 2013, 2018
    Eric van der Vlist <vdv@dyomedea.com>
    Jens Neuhalfen <http://www.neuhalfen.name/>
    Hibox Systems Oy Ab <http://www.hibox.tv>

Use freely under the term of the GPLv3.
'''

import argparse
import re
import os
import ConfigParser
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

reload(sys)
sys.setdefaultencoding('utf-8')

default_config = {
    'ssl_verify': 'yes',
    'migrate': 'true',
    'overwrite': 'true',
    'exclude_authors': 'trac',
    'uploads': ''
}

config = ConfigParser.ConfigParser(default_config)
config.read('migrate.cfg')

trac_url = config.get('source', 'url')
dest_project_name = config.get('target', 'project_name')
uploads_path = config.get('target', 'uploads')
default_group = config.get('target', 'default_group')

method = config.get('target', 'method')

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
label_colors = ast.literal_eval(config.get('issues', 'label_colors'))

default_user = None
if config.has_option('target', 'default_user'):
    default_user = config.get('target', 'default_user')

only_issues = None
if config.has_option('issues', 'only_issues'):
    only_issues = ast.literal_eval(config.get('issues', 'only_issues'))

label_prefix_translation_map = {}
if config.has_option('issues', 'label_prefix_translation_map'):
    label_prefix_translation_map = ast.literal_eval(config.get('issues', 'label_prefix_translation_map'))

parser = argparse.ArgumentParser()
parser.add_argument('--no-convert-milestones',
                    help="disable conversion of all milestones (enabled by default)",
                    action="store_true")
parser.add_argument('--issues',
                    help="migrate issues (default: false)",
                    action="store_true")
parser.add_argument("--only-issue",
                    help="migrate a specific issue instead of all.")
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

def get_dest_project_id(dest, dest_project_name):
    dest_project = dest.project_by_name(dest_project_name)
    if not dest_project:
        raise ValueError("Project '%s' not found" % dest_project_name)
    return dest_project["id"]


def get_dest_milestone_id(dest, dest_project_id, milestone_name):
    dest_milestone_id = dest.milestone_by_name(dest_project_id, milestone_name)
    if not dest_milestone_id:
        raise ValueError("Milestone '%s' of project '%s' not found" % (milestone_name, dest_project_name))
    return dest_milestone_id["id"]


def convert_issues(source, dest, dest_project_id, convert_milestones, only_issues=None):
    if only_issues is None: only_issues = []

    if overwrite and method == 'direct':
        dest.clear_issues(dest_project_id, only_issues)

    milestone_map_id = {}
    if convert_milestones:
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

        src_ticket_data = src_ticket[3]

        src_ticket_priority = src_ticket_data['priority']
        src_ticket_resolution = src_ticket_data['resolution']
        src_ticket_status = src_ticket_data['status']
        src_ticket_component = src_ticket_data['component']
        src_ticket_version = src_ticket_data['version']

        new_labels = set()
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
                new_labels.add(component.strip())

        new_state = 'opened'
        if src_ticket_status == 'new':
            new_state = 'opened'
        elif src_ticket_status == 'assigned':
            new_state = 'opened'
        elif src_ticket_status == 'reopened':
            new_state = 'reopened'
        elif src_ticket_status == 'closed':
            new_state = 'closed'
        elif src_ticket_status == 'accepted':
            new_labels.add(src_ticket_status)
        elif src_ticket_status == 'reviewing' or src_ticket_status == 'testing':
            new_labels.add(src_ticket_status)
        else:
            print("!!! unknown ticket status: %s" % src_ticket_status)

        new_labels.add(src_ticket_data['type'])

        sanitized_summary = src_ticket_data['summary']
        title_result = title_label_regexp.search(sanitized_summary)
        if title_result:
            prefix = title_result.group(1).lower()

            # Awkward way, but prefix.translate() works differently on str and unicode objects so
            # this is good enough for now.
            prefix = prefix.replace('[', '').replace(']', '').replace(':', '')
            prefix = label_prefix_translation_map.get(prefix, None)

            # Only prefixes specifically included in the whitelist get replaced.
            if prefix != None:
                new_labels.add(prefix)

                sanitized_summary = sanitized_summary[title_result.end():].strip()

        print("migrated ticket %s with labels %s" % (src_ticket_id, new_labels))

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
            labels=",".join(new_labels)
        )

        if src_ticket_version:
            if src_ticket_version == 'trunk' or src_ticket_version == 'dev':
                pass
            else:
                release_milestone_name = 'release-%s' % src_ticket_version
                if release_milestone_name not in milestone_map_id:
                    print("creating new milestone for %s" % release_milestone_name)
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
            if milestone and milestone_map_id[milestone]:
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

                        note.note = '%s[%s](/uploads/%s)' % (image_prefix, note.note, note.attachment)

                        print("migrating attachment for ticket id %s: %s" % (src_ticket_id, attachment_file_name))
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
        converted = trac2down.convert(page, os.path.dirname('/wikis/%s' % name), wiki_upload_prefix=upload_prefix)

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
    dest_project_id = get_dest_project_id(dest, dest_project_name)

    if must_convert_issues:
        convert_issues(source, dest, dest_project_id, convert_milestones, only_issues=only_issues)

    if must_convert_wiki:
        convert_wiki(source, dest)
