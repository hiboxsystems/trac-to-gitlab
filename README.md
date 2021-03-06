What
=====

 This script migrates milestones, issues and wiki pages from trac to GitLab.

Features
--------
 * Component & Issue-Type are converted to labels
 * Comments to issues are copied over
 * Supports two modes of tansfer:
  * Using GitLab web API
  * Direct access through GitLab's database and file system
 * In direct mode, attachments are transferred and the issues and notes dates and ownership are preserved
 * In API mode, attachments are not transferred, issues and notes are owned by a single user and their dates are the current date.
 * '''NOTE''': The way we have used this internally is to use direct mode for the `migrate.py` script but API mode for the other (more recently written) scripts. This is the only recommended mode at the moment; you will likely have to patch the code to get it working if you want to use "direct mode for everything" or "API mode for everything".

How
====

Migrating a trac project to GitLab is a relatively complex process involving four steps:

 * Create a new project
 * Migrate the repository (can just be cloning a git repository if the trac project is already using git or could involve converting from subversion using git-svn)
 * Create the users for the project
 * Migrate issues and milestones
 * Migrate wiki pages

This script takes care of the last two bullet points and provides help for the third one.

 Usage:

  1. Install dependencies: `pip install -r requirements.txt`
  1. `cp migrate.cfg.example migrate.cfg`
  1. `cp migrate_config.py.example migrate_config.py`
  1. Edit `migrate.cfg`, tweaking the values to your needs. Likewise with `migrate_config.py`.
  1. Run `./collect-users.py` to extract the user names from Trac
  1. Update `migrate.cfg` to map users to email addresses.
  1. Create `users.py` with your list of users.
  1. Run `./create-missing-users.py` to create all missing users in GitLab.
  1. Run (`./migrate.py`). Make sure you test it on a test project prior, if you run it twice against the same project you will get duplicated issues unless you're using direct access with overwrite set to yes.

Other scripts
=============

1. `./delete-projects.py` - deletes all registered projects (good for re-migrating over and over again) based on `projects.py` config. See `projects.py.example` for an example config.
1. `./create-projects.py` - creates projects based on `projects.py` config.

Issues and milestones are copied to GitLab.

Wiki pages are copied to a folder on your machine and must be pushed into GitLab using wiki's git access.

GitLab versions
===============

The database model should correspond to the version of GitLab that you are using.

This repo contains models for multiple versions (gitlab_direct/model<version>.py) and the version number should be updated correspondingly in the imports in [gitlab_direct/__init__.py](gitlab_direct/__init__.py) and [gitlab_direct/Connection.py](gitlab_direct/Connection.py).

To support a new version, use pwiz.py:

```
$ pwiz.py -e postgresql -u gitlab gitlabhq_production > gitlab_direct/model<version>.py
```

Manual updates must then be applied, see for instance the [manual updates for 6.4](https://gitlab.dyomedea.com/vdv/trac-to-gitlab/commit/8a5592a7b996054849bf7ac21fd5fec267db1df9).

Configuration
=============

The configuration must be located in a file named "migrate.cfg"

Source
-------

 * `url` - xmlrpc url to trac, e.g. `https://user:secret@www.example.com/projects/thisismyproject/login/xmlrpc`

Target
-------

 * `project_name` - the destination project including the paths to it. Basically the rest of the clone url minus the ".git". E.g. `jens.neuhalfen/task-ninja`.
 * `method` - direct or api

API mode:

 * `url` - e.g. `https://www.exmple.com/gitlab/api/v3`
 * `access_token` - the personal access token of the user creating all the issues. Found on the account page,  e.g. `secretsecretsecret`
 * `ssl_verify` - set to `no` to disable verification of SSL server certificates (enabled by default)
 * `delete_users` - set to `true` if you want all users to be recreated on each run. (disabled by default)
 * `ldap_uid_pattern` - used to set the LDAP pattern for the UID field. Used by [create-missing-users.py](create-missing-users.py)
 * `default_group` - this should be the default GitLab group you want to add users to upon creation.

Direct mode:

 * `overwrite` - if set to yes, the milestones and issues are cleared for this projects and issues are recreated with their trac id (useful to preserve trac links)
 * `db-name` - MySQL database name
 * `db-user` - MySQL user name
 * `db-password` - MySQL password
 * `uploads` - GitLab uploads directory
 * `usernames` Comma separed list of username mappings such as: `trac1->git1, trac2->git2`

Wiki
----

 * `target-directory` - Directory in which the wiki pages should be written

Issues
------

 * `label_colors` -- maps particular labels to colors (see `migrate.cfg.example` for example syntax)
 * `label_prefix_translation_map` -- maps issue prefixes to labels
 * `only_issues` -- (optional) array that limits the conversion to particular issues. If provided, other existing issues in the database are retained.

Licenses
========

GPL license version 3.0: [LICENSE](LICENSE)

`gitlab_direct/model110.py` was copied from
https://github.com/tracboat/tracboat which is licensed under the GPLv3.

History
=======

 * The main program has been cloned from https://gitlab.dyomedea.com/vdv/trac-to-gitlab which itself has been cloned from https://github.com/neuhalje/hack-copy-track-issues-to-gitlab
 * Trac2down.py (the conversion of trac wiki markup to markdown) has been cloned from https://gist.github.com/sgk/1286682 and https://gist.github.com/tcchau/4628317

Requirements
==============

 * Python 2.7, xmlrpclib, requests
 * Trac with [XML-RPC plugin](http://trac-hacks.org/wiki/XmlRpcPlugin) enabled
 * Gitlab

 And also, if you use the direct access to GitLab's database:

 * [peewee](https://github.com/coleifer/peewee)
 * [PyMySQL](https://github.com/PyMySQL/PyMySQL)
