from peewee import *

database_proxy = Proxy()

class UnknownField(object):
    pass

class BaseModel(Model):
    class Meta:
        database = database_proxy

class AbuseReports(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    message = TextField(null=True)
    message_html = TextField(null=True)
    reporter = IntegerField(db_column='reporter_id', null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', null=True)

    class Meta:
        db_table = 'abuse_reports'

class Appearances(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField()
    description_html = TextField(null=True)
    footer_message = TextField(null=True)
    footer_message_html = TextField(null=True)
    header_logo = CharField(null=True)
    header_message = TextField(null=True)
    header_message_html = TextField(null=True)
    light_logo = CharField(null=True)
    logo = CharField(null=True)
    message_background_color = TextField(null=True)
    message_font_color = TextField(null=True)
    new_project_guidelines = TextField(null=True)
    new_project_guidelines_html = TextField(null=True)
    title = CharField()
    updated_at = DateTimeField()

    class Meta:
        db_table = 'appearances'

class ApplicationSettings(BaseModel):
    admin_notification_email = CharField(null=True)
    after_sign_out_path = CharField(null=True)
    after_sign_up_text = TextField(null=True)
    after_sign_up_text_html = TextField(null=True)
    akismet_api_key = CharField(null=True)
    akismet_enabled = BooleanField(null=True)
    allow_group_owners_to_manage_ldap = BooleanField()
    allow_local_requests_from_hooks_and_services = BooleanField()
    authorized_keys_enabled = BooleanField()
    auto_devops_domain = CharField(null=True)
    auto_devops_enabled = BooleanField()
    cached_markdown_version = IntegerField(null=True)
    check_namespace_plan = BooleanField()
    circuitbreaker_access_retries = IntegerField(null=True)
    circuitbreaker_check_interval = IntegerField()
    circuitbreaker_failure_count_threshold = IntegerField(null=True)
    circuitbreaker_failure_reset_time = IntegerField(null=True)
    circuitbreaker_storage_timeout = IntegerField(null=True)
    clientside_sentry_dsn = CharField(null=True)
    clientside_sentry_enabled = BooleanField()
    container_registry_token_expire_delay = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    default_artifacts_expire_in = CharField()
    default_branch_protection = IntegerField(null=True)
    default_group_visibility = IntegerField(null=True)
    default_project_creation = IntegerField()
    default_project_visibility = IntegerField(null=True)
    default_projects_limit = IntegerField(null=True)
    default_snippet_visibility = IntegerField(null=True)
    disabled_oauth_sign_in_sources = TextField(null=True)
    domain_blacklist = TextField(null=True)
    domain_blacklist_enabled = BooleanField(null=True)
    domain_whitelist = TextField(null=True)
    dsa_key_restriction = IntegerField()
    ecdsa_key_restriction = IntegerField()
    ed25519_key_restriction = IntegerField()
    elasticsearch_aws = BooleanField()
    elasticsearch_aws_access_key = CharField(null=True)
    elasticsearch_aws_region = CharField(null=True)
    elasticsearch_aws_secret_access_key = CharField(null=True)
    elasticsearch_experimental_indexer = BooleanField(null=True)
    elasticsearch_indexing = BooleanField()
    elasticsearch_search = BooleanField()
    elasticsearch_url = CharField(null=True)
    email_additional_text = CharField(null=True)
    email_author_in_body = BooleanField(null=True)
    enabled_git_access_protocol = CharField(null=True)
    encrypted_external_auth_client_key = TextField(null=True)
    encrypted_external_auth_client_key_iv = CharField(null=True)
    encrypted_external_auth_client_key_pass = CharField(null=True)
    encrypted_external_auth_client_key_pass_iv = CharField(null=True)
    external_auth_client_cert = TextField(null=True)
    external_authorization_service_default_label = CharField(null=True)
    external_authorization_service_enabled = BooleanField()
    external_authorization_service_timeout = FloatField(null=True)
    external_authorization_service_url = CharField(null=True)
    geo_status_timeout = IntegerField(null=True)
    gitaly_timeout_default = IntegerField()
    gitaly_timeout_fast = IntegerField()
    gitaly_timeout_medium = IntegerField()
    gravatar_enabled = BooleanField(null=True)
    hashed_storage_enabled = BooleanField()
    health_check_access_token = CharField(null=True)
    help_page_hide_commercial_content = BooleanField(null=True)
    help_page_support_url = CharField(null=True)
    help_page_text = TextField(null=True)
    help_page_text_html = TextField(null=True)
    help_text = TextField(null=True)
    home_page_url = CharField(null=True)
    housekeeping_bitmaps_enabled = BooleanField()
    housekeeping_enabled = BooleanField()
    housekeeping_full_repack_period = IntegerField()
    housekeeping_gc_period = IntegerField()
    housekeeping_incremental_repack_period = IntegerField()
    html_emails_enabled = BooleanField(null=True)
    import_sources = TextField(null=True)
    koding_enabled = BooleanField(null=True)
    koding_url = CharField(null=True)
    max_artifacts_size = IntegerField()
    max_attachment_size = IntegerField()
    max_pages_size = IntegerField()
    metrics_enabled = BooleanField(null=True)
    metrics_host = CharField(null=True)
    metrics_method_call_threshold = IntegerField(null=True)
    metrics_packet_size = IntegerField(null=True)
    metrics_pool_size = IntegerField(null=True)
    metrics_port = IntegerField(null=True)
    metrics_sample_interval = IntegerField(null=True)
    metrics_timeout = IntegerField(null=True)
    mirror_available = BooleanField()
    mirror_capacity_threshold = IntegerField()
    mirror_max_capacity = IntegerField()
    mirror_max_delay = IntegerField()
    pages_domain_verification_enabled = BooleanField()
    password_authentication_enabled_for_git = BooleanField()
    password_authentication_enabled_for_web = BooleanField(null=True)
    performance_bar_allowed_group = IntegerField(db_column='performance_bar_allowed_group_id', null=True)
    plantuml_enabled = BooleanField(null=True)
    plantuml_url = CharField(null=True)
    polling_interval_multiplier = DecimalField()
    project_export_enabled = BooleanField()
    prometheus_metrics_enabled = BooleanField()
    recaptcha_enabled = BooleanField(null=True)
    recaptcha_private_key = CharField(null=True)
    recaptcha_site_key = CharField(null=True)
    repository_checks_enabled = BooleanField(null=True)
    repository_size_limit = BigIntegerField(null=True)
    repository_storages = CharField(null=True)
    require_two_factor_authentication = BooleanField(null=True)
    restricted_visibility_levels = TextField(null=True)
    rsa_key_restriction = IntegerField()
    runners_registration_token = CharField(null=True)
    send_user_confirmation_email = BooleanField(null=True)
    sentry_dsn = CharField(null=True)
    sentry_enabled = BooleanField(null=True)
    session_expire_delay = IntegerField()
    shared_runners_enabled = BooleanField()
    shared_runners_minutes = IntegerField()
    shared_runners_text = TextField(null=True)
    shared_runners_text_html = TextField(null=True)
    sidekiq_throttling_enabled = BooleanField(null=True)
    sidekiq_throttling_factor = DecimalField(null=True)
    sidekiq_throttling_queues = CharField(null=True)
    sign_in_text = TextField(null=True)
    sign_in_text_html = TextField(null=True)
    signup_enabled = BooleanField(null=True)
    slack_app_enabled = BooleanField(null=True)
    slack_app = CharField(db_column='slack_app_id', null=True)
    slack_app_secret = CharField(null=True)
    slack_app_verification_token = CharField(null=True)
    terminal_max_session_time = IntegerField()
    throttle_authenticated_api_enabled = BooleanField()
    throttle_authenticated_api_period_in_seconds = IntegerField()
    throttle_authenticated_api_requests_per_period = IntegerField()
    throttle_authenticated_web_enabled = BooleanField()
    throttle_authenticated_web_period_in_seconds = IntegerField()
    throttle_authenticated_web_requests_per_period = IntegerField()
    throttle_unauthenticated_enabled = BooleanField()
    throttle_unauthenticated_period_in_seconds = IntegerField()
    throttle_unauthenticated_requests_per_period = IntegerField()
    two_factor_grace_period = IntegerField(null=True)
    unique_ips_limit_enabled = BooleanField()
    unique_ips_limit_per_user = IntegerField(null=True)
    unique_ips_limit_time_window = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    usage_ping_enabled = BooleanField()
    user_default_external = BooleanField()
    user_oauth_applications = BooleanField(null=True)
    uuid = CharField(null=True)
    version_check_enabled = BooleanField(null=True)

    class Meta:
        db_table = 'application_settings'

class Projects(BaseModel):
    approvals_before_merge = IntegerField()
    archived = BooleanField()
    auto_cancel_pending_pipelines = IntegerField()
    avatar = CharField(null=True)
    build_allow_git_fetch = BooleanField()
    build_coverage_regex = CharField(null=True)
    build_timeout = IntegerField()
    cached_markdown_version = IntegerField(null=True)
    ci_config_path = CharField(null=True)
    ci = IntegerField(db_column='ci_id', index=True, null=True)
    container_registry_enabled = BooleanField(null=True)
    created_at = DateTimeField(index=True, null=True)
    creator = IntegerField(db_column='creator_id', index=True, null=True)
    delete_error = TextField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    disable_overriding_approvers_per_merge_request = BooleanField(null=True)
    external_authorization_classification_label = CharField(null=True)
    external_webhook_token = CharField(null=True)
    has_external_issue_tracker = BooleanField(null=True)
    has_external_wiki = BooleanField(null=True)
    import_error = TextField(null=True)
    import_jid = CharField(null=True)
    import_source = CharField(null=True)
    import_status = CharField(null=True)
    import_type = CharField(null=True)
    import_url = CharField(null=True)
    issues_template = TextField(null=True)
    jobs_cache_index = IntegerField(null=True)
    last_activity_at = DateTimeField(index=True, null=True)
    last_repository_check_at = DateTimeField(null=True)
    last_repository_check_failed = BooleanField(index=True, null=True)
    last_repository_updated_at = DateTimeField(index=True, null=True)
    lfs_enabled = BooleanField(null=True)
    merge_requests_ff_only_enabled = BooleanField()
    merge_requests_rebase_enabled = BooleanField()
    merge_requests_template = TextField(null=True)
    mirror = BooleanField()
    mirror_last_successful_update_at = DateTimeField(index=True, null=True)
    mirror_last_update_at = DateTimeField(null=True)
    mirror_overwrites_diverged_branches = BooleanField(null=True)
    mirror_trigger_builds = BooleanField()
    mirror_user = IntegerField(db_column='mirror_user_id', null=True)
    name = CharField(index=True, null=True)
    namespace = IntegerField(db_column='namespace_id', index=True)
    only_allow_merge_if_all_discussions_are_resolved = BooleanField(null=True)
    only_allow_merge_if_pipeline_succeeds = BooleanField()
    only_mirror_protected_branches = BooleanField(null=True)
    pages_https_only = BooleanField(null=True)
    path = CharField(index=True, null=True)
    pending_delete = BooleanField(index=True, null=True)
    printing_merge_request_link_enabled = BooleanField()
    public_builds = BooleanField()
    pull_mirror_available_overridden = BooleanField(null=True)
    remote_mirror_available_overridden = BooleanField(null=True)
    repository_read_only = BooleanField(null=True)
    repository_size_limit = BigIntegerField(null=True)
    repository_storage = CharField(index=True)
    request_access_enabled = BooleanField()
    reset_approvals_on_push = BooleanField(null=True)
    resolve_outdated_diff_discussions = BooleanField(null=True)
    runners_token = CharField(index=True, null=True)
    service_desk_enabled = BooleanField(null=True)
    shared_runners_enabled = BooleanField()
    star_count = IntegerField(index=True)
    storage_version = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField(index=True)

    class Meta:
        db_table = 'projects'

class Users(BaseModel):
    admin = BooleanField(index=True)
    admin_email_unsubscribed_at = DateTimeField(null=True)
    auditor = BooleanField()
    avatar = CharField(null=True)
    bio = CharField(null=True)
    can_create_group = BooleanField()
    can_create_team = BooleanField()
    color_scheme = IntegerField(db_column='color_scheme_id')
    confirmation_sent_at = DateTimeField(null=True)
    confirmation_token = CharField(null=True, unique=True)
    confirmed_at = DateTimeField(null=True)
    consumed_timestep = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    created_by = IntegerField(db_column='created_by_id', null=True)
    current_sign_in_at = DateTimeField(null=True)
    current_sign_in_ip = CharField(null=True)
    dashboard = IntegerField(null=True)
    email = CharField(index=True)
    email_opted_in = BooleanField(null=True)
    email_opted_in_at = DateTimeField(null=True)
    email_opted_in_ip = CharField(null=True)
    email_opted_in_source = IntegerField(db_column='email_opted_in_source_id', null=True)
    encrypted_otp_secret = CharField(null=True)
    encrypted_otp_secret_iv = CharField(null=True)
    encrypted_otp_secret_salt = CharField(null=True)
    encrypted_password = CharField()
    external = BooleanField(null=True)
    failed_attempts = IntegerField(null=True)
    ghost = BooleanField(index=True, null=True)
    hide_no_password = BooleanField(null=True)
    hide_no_ssh_key = BooleanField(null=True)
    hide_project_limit = BooleanField(null=True)
    incoming_email_token = CharField(index=True, null=True)
    last_activity_on = DateField(null=True)
    last_credential_check_at = DateTimeField(null=True)
    last_sign_in_at = DateTimeField(null=True)
    last_sign_in_ip = CharField(null=True)
    layout = IntegerField(null=True)
    linkedin = CharField()
    location = CharField(null=True)
    locked_at = DateTimeField(null=True)
    name = CharField(index=True, null=True)
    note = TextField(null=True)
    notification_email = CharField(null=True)
    notified_of_own_activity = BooleanField(null=True)
    organization = CharField(null=True)
    otp_backup_codes = TextField(null=True)
    otp_grace_period_started_at = DateTimeField(null=True)
    otp_required_for_login = BooleanField()
    password_automatically_set = BooleanField(null=True)
    password_expires_at = DateTimeField(null=True)
    preferred_language = CharField(null=True)
    project_view = IntegerField(null=True)
    projects_limit = IntegerField()
    public_email = CharField()
    remember_created_at = DateTimeField(null=True)
    require_two_factor_authentication_from_group = BooleanField()
    reset_password_sent_at = DateTimeField(null=True)
    reset_password_token = CharField(null=True, unique=True)
    rss_token = CharField(index=True, null=True)
    sign_in_count = IntegerField(null=True)
    skype = CharField()
    state = CharField(index=True, null=True)
    support_bot = BooleanField(index=True, null=True)
    theme = IntegerField(db_column='theme_id', null=True)
    twitter = CharField()
    two_factor_grace_period = IntegerField()
    unconfirmed_email = CharField(null=True)
    unlock_token = CharField(null=True)
    updated_at = DateTimeField(null=True)
    username = CharField(index=True, null=True)
    website_url = CharField()

    class Meta:
        db_table = 'users'

class CiPipelineSchedules(BaseModel):
    active = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    cron = CharField(null=True)
    cron_timezone = CharField(null=True)
    description = CharField(null=True)
    next_run_at = DateTimeField(null=True)
    owner = ForeignKeyField(db_column='owner_id', null=True, rel_model=Users, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    ref = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'ci_pipeline_schedules'
        indexes = (
            (('next_run_at', 'active'), False),
        )

class CiPipelines(BaseModel):
    auto_canceled_by = ForeignKeyField(db_column='auto_canceled_by_id', null=True, rel_model='self', to_field='id')
    before_sha = CharField(null=True)
    committed_at = DateTimeField(null=True)
    config_source = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    duration = IntegerField(null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    pipeline_schedule = ForeignKeyField(db_column='pipeline_schedule_id', null=True, rel_model=CiPipelineSchedules, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    protected = BooleanField(null=True)
    ref = CharField(null=True)
    sha = CharField(null=True)
    source = IntegerField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(index=True, null=True)
    tag = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', index=True, null=True)
    yaml_errors = TextField(null=True)

    class Meta:
        db_table = 'ci_pipelines'
        indexes = (
            (('id', 'ref', 'project', 'status'), False),
            (('sha', 'project'), False),
        )

# Possible reference cycle: merge_requests
class MergeRequestDiffs(BaseModel):
    base_commit_sha = CharField(null=True)
    commits_count = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    head_commit_sha = CharField(null=True)
    merge_request = ForeignKeyField(db_column='merge_request_id', rel_model=MergeRequests, to_field='id')
    real_size = CharField(null=True)
    start_commit_sha = CharField(null=True)
    state = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'merge_request_diffs'
        indexes = (
            (('id', 'merge_request'), False),
        )

class Plans(BaseModel):
    active_pipelines_limit = IntegerField(null=True)
    created_at = DateTimeField()
    name = CharField(index=True, null=True)
    pipeline_size_limit = IntegerField(null=True)
    title = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'plans'

class Namespaces(BaseModel):
    avatar = CharField(null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    description = CharField()
    description_html = TextField(null=True)
    ldap_sync_error = CharField(null=True)
    ldap_sync_last_successful_update_at = DateTimeField(index=True, null=True)
    ldap_sync_last_sync_at = DateTimeField(null=True)
    ldap_sync_last_update_at = DateTimeField(index=True, null=True)
    ldap_sync_status = CharField()
    lfs_enabled = BooleanField(null=True)
    membership_lock = BooleanField(null=True)
    name = CharField(index=True)
    owner = IntegerField(db_column='owner_id', index=True, null=True)
    parent = IntegerField(db_column='parent_id', null=True)
    path = CharField(index=True)
    plan = ForeignKeyField(db_column='plan_id', null=True, rel_model=Plans, to_field='id')
    project_creation_level = IntegerField(null=True)
    repository_size_limit = BigIntegerField(null=True)
    request_access_enabled = BooleanField()
    require_two_factor_authentication = BooleanField(index=True)
    share_with_group_lock = BooleanField(null=True)
    shared_runners_minutes_limit = IntegerField(null=True)
    two_factor_grace_period = IntegerField()
    type = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField()

    class Meta:
        db_table = 'namespaces'
        indexes = (
            (('id', 'parent'), True),
            (('parent', 'name'), True),
        )

class Milestones(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    due_date = DateField(index=True, null=True)
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    iid = IntegerField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    start_date = DateField(null=True)
    state = CharField(null=True)
    title = CharField(index=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'milestones'
        indexes = (
            (('project', 'iid'), True),
        )

class MergeRequests(BaseModel):
    allow_maintainer_to_push = BooleanField(null=True)
    approvals_before_merge = IntegerField(null=True)
    assignee = ForeignKeyField(db_column='assignee_id', null=True, rel_model=Users, to_field='id')
    author = ForeignKeyField(db_column='author_id', null=True, rel_model=Users, related_name='users_author_set', to_field='id')
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    discussion_locked = BooleanField(null=True)
    head_pipeline = ForeignKeyField(db_column='head_pipeline_id', null=True, rel_model=CiPipelines, to_field='id')
    iid = IntegerField(null=True)
    in_progress_merge_commit_sha = CharField(null=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by = IntegerField(db_column='last_edited_by_id', null=True)
    latest_merge_request_diff = ForeignKeyField(db_column='latest_merge_request_diff_id', null=True, rel_model=MergeRequestDiffs, to_field='id')
    lock_version = IntegerField(null=True)
    merge_commit_sha = CharField(null=True)
    merge_error = TextField(null=True)
    merge_jid = CharField(null=True)
    merge_params = TextField(null=True)
    merge_status = CharField()
    merge_user = ForeignKeyField(db_column='merge_user_id', null=True, rel_model=Users, related_name='users_merge_user_set', to_field='id')
    merge_when_pipeline_succeeds = BooleanField()
    milestone = ForeignKeyField(db_column='milestone_id', null=True, rel_model=Milestones, to_field='id')
    rebase_commit_sha = CharField(null=True)
    source_branch = CharField(index=True)
    source_project = ForeignKeyField(db_column='source_project_id', null=True, rel_model=Projects, to_field='id')
    squash = BooleanField()
    state = CharField()
    target_branch = CharField(index=True)
    target_project = ForeignKeyField(db_column='target_project_id', rel_model=Projects, related_name='projects_target_project_set', to_field='id')
    time_estimate = IntegerField(null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(null=True)
    updated_by = ForeignKeyField(db_column='updated_by_id', null=True, rel_model=Users, related_name='users_updated_by_set', to_field='id')

    class Meta:
        db_table = 'merge_requests'
        indexes = (
            (('merge_commit_sha', 'target_project', 'id'), False),
            (('source_branch', 'source_project'), False),
            (('source_project', 'source_branch'), False),
            (('target_project', 'iid'), True),
        )

class Approvals(BaseModel):
    created_at = DateTimeField(null=True)
    merge_request = ForeignKeyField(db_column='merge_request_id', rel_model=MergeRequests, to_field='id')
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id')

    class Meta:
        db_table = 'approvals'

class ApproverGroups(BaseModel):
    created_at = DateTimeField(null=True)
    group = ForeignKeyField(db_column='group_id', rel_model=Namespaces, to_field='id')
    target = IntegerField(db_column='target_id')
    target_type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'approver_groups'
        indexes = (
            (('target', 'target_type'), False),
        )

class Approvers(BaseModel):
    created_at = DateTimeField(null=True)
    target = IntegerField(db_column='target_id')
    target_type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', index=True)

    class Meta:
        db_table = 'approvers'
        indexes = (
            (('target', 'target_type'), False),
        )

class AuditEvents(BaseModel):
    author = IntegerField(db_column='author_id')
    created_at = DateTimeField(null=True)
    details = TextField(null=True)
    entity = IntegerField(db_column='entity_id')
    entity_type = CharField()
    type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'audit_events'
        indexes = (
            (('entity', 'entity_type'), False),
        )

class AwardEmoji(BaseModel):
    awardable = IntegerField(db_column='awardable_id', null=True)
    awardable_type = CharField(null=True)
    created_at = DateTimeField(null=True)
    name = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', null=True)

    class Meta:
        db_table = 'award_emoji'
        indexes = (
            (('awardable', 'awardable_type'), False),
            (('name', 'user'), False),
        )

class Badges(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    image_url = CharField()
    link_url = CharField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    type = CharField()
    updated_at = DateTimeField()

    class Meta:
        db_table = 'badges'

class Boards(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    milestone = IntegerField(db_column='milestone_id', index=True, null=True)
    name = CharField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    updated_at = DateTimeField()
    weight = IntegerField(null=True)

    class Meta:
        db_table = 'boards'

class BoardAssignees(BaseModel):
    assignee = ForeignKeyField(db_column='assignee_id', rel_model=Users, to_field='id')
    board = ForeignKeyField(db_column='board_id', rel_model=Boards, to_field='id')

    class Meta:
        db_table = 'board_assignees'
        indexes = (
            (('board', 'assignee'), True),
        )

class Labels(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    description_html = TextField(null=True)
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    template = BooleanField(index=True, null=True)
    title = CharField(index=True, null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'labels'
        indexes = (
            (('title', 'group', 'project'), True),
            (('type', 'project'), False),
        )

class BoardLabels(BaseModel):
    board = ForeignKeyField(db_column='board_id', rel_model=Boards, to_field='id')
    label = ForeignKeyField(db_column='label_id', rel_model=Labels, to_field='id')

    class Meta:
        db_table = 'board_labels'
        indexes = (
            (('board', 'label'), True),
        )

class BroadcastMessages(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField()
    ends_at = DateTimeField()
    font = CharField(null=True)
    message = TextField()
    message_html = TextField()
    starts_at = DateTimeField()
    updated_at = DateTimeField()

    class Meta:
        db_table = 'broadcast_messages'
        indexes = (
            (('id', 'starts_at', 'ends_at'), False),
        )

class ChatNames(BaseModel):
    chat = CharField(db_column='chat_id')
    chat_name = CharField(null=True)
    created_at = DateTimeField()
    last_used_at = DateTimeField(null=True)
    service = IntegerField(db_column='service_id')
    team_domain = CharField(null=True)
    team = CharField(db_column='team_id')
    updated_at = DateTimeField()
    user = IntegerField(db_column='user_id')

    class Meta:
        db_table = 'chat_names'
        indexes = (
            (('service', 'team', 'chat'), True),
            (('user', 'service'), True),
        )

class ChatTeams(BaseModel):
    created_at = DateTimeField()
    name = CharField(null=True)
    namespace = ForeignKeyField(db_column='namespace_id', rel_model=Namespaces, to_field='id', unique=True)
    team = CharField(db_column='team_id', null=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'chat_teams'

class CiBuildTraceSectionNames(BaseModel):
    name = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')

    class Meta:
        db_table = 'ci_build_trace_section_names'
        indexes = (
            (('project', 'name'), True),
        )

class CiStages(BaseModel):
    created_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    name = CharField(null=True)
    pipeline = ForeignKeyField(db_column='pipeline_id', null=True, rel_model=CiPipelines, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    status = IntegerField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'ci_stages'
        indexes = (
            (('pipeline', 'name'), True),
        )

class CiBuilds(BaseModel):
    allow_failure = BooleanField()
    artifacts_expire_at = DateTimeField(index=True, null=True)
    artifacts_file = TextField(null=True)
    artifacts_file_store = IntegerField(null=True)
    artifacts_metadata = TextField(null=True)
    artifacts_metadata_store = IntegerField(null=True)
    artifacts_size = BigIntegerField(null=True)
    auto_canceled_by = ForeignKeyField(db_column='auto_canceled_by_id', null=True, rel_model=CiPipelines, to_field='id')
    commands = TextField(null=True)
    commit = IntegerField(db_column='commit_id', null=True)
    coverage = FloatField(null=True)
    coverage_regex = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    environment = CharField(null=True)
    erased_at = DateTimeField(null=True)
    erased_by = IntegerField(db_column='erased_by_id', null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    name = CharField(null=True)
    options = TextField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    protected = BooleanField(index=True, null=True)
    queued_at = DateTimeField(null=True)
    ref = CharField(null=True)
    retried = BooleanField(null=True)
    runner = IntegerField(db_column='runner_id', index=True, null=True)
    stage = CharField(null=True)
    stage_id = ForeignKeyField(db_column='stage_id', null=True, rel_model=CiStages, to_field='id')
    stage_idx = IntegerField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(index=True, null=True)
    tag = BooleanField(null=True)
    target_url = CharField(null=True)
    token = CharField(null=True, unique=True)
    trace = TextField(null=True)
    trigger_request = IntegerField(db_column='trigger_request_id', null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    user = IntegerField(db_column='user_id', index=True, null=True)
    when = CharField(null=True)
    yaml_variables = TextField(null=True)

    class Meta:
        db_table = 'ci_builds'
        indexes = (
            (('commit', 'created_at', 'stage_idx'), False),
            (('commit', 'name', 'type', 'ref'), False),
            (('commit', 'ref', 'type'), False),
            (('id', 'project'), False),
            (('runner', 'status', 'type'), False),
            (('type', 'status', 'commit'), False),
        )

class CiBuildTraceSections(BaseModel):
    build = ForeignKeyField(db_column='build_id', rel_model=CiBuilds, to_field='id')
    byte_end = BigIntegerField()
    byte_start = BigIntegerField()
    date_end = DateTimeField()
    date_start = DateTimeField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    section_name = ForeignKeyField(db_column='section_name_id', rel_model=CiBuildTraceSectionNames, to_field='id')

    class Meta:
        db_table = 'ci_build_trace_sections'
        indexes = (
            (('build', 'section_name'), True),
        )

class CiBuildsMetadata(BaseModel):
    build = ForeignKeyField(db_column='build_id', rel_model=CiBuilds, to_field='id', unique=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    timeout = IntegerField(null=True)
    timeout_source = IntegerField()

    class Meta:
        db_table = 'ci_builds_metadata'

class CiGroupVariables(BaseModel):
    created_at = DateTimeField()
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    group = ForeignKeyField(db_column='group_id', rel_model=Namespaces, to_field='id')
    key = CharField()
    protected = BooleanField()
    updated_at = DateTimeField()
    value = TextField(null=True)

    class Meta:
        db_table = 'ci_group_variables'
        indexes = (
            (('key', 'group'), True),
        )

class CiJobArtifacts(BaseModel):
    created_at = DateTimeField()
    expire_at = DateTimeField(null=True)
    file = CharField(null=True)
    file_sha256 = BlobField(null=True)
    file_store = IntegerField(index=True, null=True)
    file_type = IntegerField()
    job = ForeignKeyField(db_column='job_id', rel_model=CiBuilds, to_field='id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    size = BigIntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'ci_job_artifacts'
        indexes = (
            (('job', 'expire_at'), False),
            (('job', 'file_type'), True),
        )

class CiPipelineChatData(BaseModel):
    chat_name = ForeignKeyField(db_column='chat_name_id', rel_model=ChatNames, to_field='id')
    id = BigIntegerField(primary_key=True)
    pipeline = ForeignKeyField(db_column='pipeline_id', rel_model=CiPipelines, to_field='id', unique=True)
    response_url = TextField()

    class Meta:
        db_table = 'ci_pipeline_chat_data'

class CiPipelineScheduleVariables(BaseModel):
    created_at = DateTimeField(null=True)
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline_schedule = ForeignKeyField(db_column='pipeline_schedule_id', rel_model=CiPipelineSchedules, to_field='id')
    updated_at = DateTimeField(null=True)
    value = TextField(null=True)

    class Meta:
        db_table = 'ci_pipeline_schedule_variables'
        indexes = (
            (('key', 'pipeline_schedule'), True),
        )

class CiPipelineVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline = ForeignKeyField(db_column='pipeline_id', rel_model=CiPipelines, to_field='id')
    value = TextField(null=True)

    class Meta:
        db_table = 'ci_pipeline_variables'
        indexes = (
            (('key', 'pipeline'), True),
        )

class CiRunnerProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    runner = IntegerField(db_column='runner_id', index=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'ci_runner_projects'

class CiRunners(BaseModel):
    access_level = IntegerField()
    active = BooleanField()
    architecture = CharField(null=True)
    contacted_at = DateTimeField(index=True, null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    ip_address = CharField(null=True)
    is_shared = BooleanField(index=True, null=True)
    locked = BooleanField(index=True)
    maximum_timeout = IntegerField(null=True)
    name = CharField(null=True)
    platform = CharField(null=True)
    revision = CharField(null=True)
    run_untagged = BooleanField()
    token = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    version = CharField(null=True)

    class Meta:
        db_table = 'ci_runners'

class CiSourcesPipelines(BaseModel):
    pipeline = ForeignKeyField(db_column='pipeline_id', null=True, rel_model=CiPipelines, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    source_job = ForeignKeyField(db_column='source_job_id', null=True, rel_model=CiBuilds, to_field='id')
    source_pipeline = ForeignKeyField(db_column='source_pipeline_id', null=True, rel_model=CiPipelines, related_name='ci_pipelines_source_pipeline_set', to_field='id')
    source_project = ForeignKeyField(db_column='source_project_id', null=True, rel_model=Projects, related_name='projects_source_project_set', to_field='id')

    class Meta:
        db_table = 'ci_sources_pipelines'

class CiTriggers(BaseModel):
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    owner = ForeignKeyField(db_column='owner_id', null=True, rel_model=Users, to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    ref = CharField(null=True)
    token = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'ci_triggers'

class CiTriggerRequests(BaseModel):
    commit = IntegerField(db_column='commit_id', index=True, null=True)
    created_at = DateTimeField(null=True)
    trigger = ForeignKeyField(db_column='trigger_id', rel_model=CiTriggers, to_field='id')
    updated_at = DateTimeField(null=True)
    variables = TextField(null=True)

    class Meta:
        db_table = 'ci_trigger_requests'

class CiVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    environment_scope = CharField()
    key = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    protected = BooleanField()
    value = TextField(null=True)

    class Meta:
        db_table = 'ci_variables'
        indexes = (
            (('key', 'project', 'environment_scope'), True),
        )

class Clusters(BaseModel):
    created_at = DateTimeField()
    enabled = BooleanField(index=True, null=True)
    environment_scope = CharField()
    name = CharField()
    platform_type = IntegerField(null=True)
    provider_type = IntegerField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'clusters'

class ClusterPlatformsKubernetes(BaseModel):
    api_url = TextField(null=True)
    ca_cert = TextField(null=True)
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id', unique=True)
    created_at = DateTimeField()
    encrypted_password = TextField(null=True)
    encrypted_password_iv = CharField(null=True)
    encrypted_token = TextField(null=True)
    encrypted_token_iv = CharField(null=True)
    namespace = CharField(null=True)
    updated_at = DateTimeField()
    username = CharField(null=True)

    class Meta:
        db_table = 'cluster_platforms_kubernetes'

class ClusterProjects(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id')
    created_at = DateTimeField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'cluster_projects'

class ClusterProvidersGcp(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id', unique=True)
    created_at = DateTimeField()
    encrypted_access_token = TextField(null=True)
    encrypted_access_token_iv = CharField(null=True)
    endpoint = CharField(null=True)
    gcp_project = CharField(db_column='gcp_project_id')
    machine_type = CharField(null=True)
    num_nodes = IntegerField()
    operation = CharField(db_column='operation_id', null=True)
    status = IntegerField(null=True)
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    zone = CharField()

    class Meta:
        db_table = 'cluster_providers_gcp'

class ClustersApplicationsHelm(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id')
    created_at = DateTimeField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        db_table = 'clusters_applications_helm'

class ClustersApplicationsIngress(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id')
    cluster_ip = CharField(null=True)
    created_at = DateTimeField()
    external_ip = CharField(null=True)
    ingress_type = IntegerField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        db_table = 'clusters_applications_ingress'

class ClustersApplicationsPrometheus(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id')
    created_at = DateTimeField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        db_table = 'clusters_applications_prometheus'

class ClustersApplicationsRunners(BaseModel):
    cluster = ForeignKeyField(db_column='cluster_id', rel_model=Clusters, to_field='id', unique=True)
    created_at = DateTimeField()
    privileged = BooleanField()
    runner = ForeignKeyField(db_column='runner_id', null=True, rel_model=CiRunners, to_field='id')
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        db_table = 'clusters_applications_runners'

class ContainerRepositories(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'container_repositories'
        indexes = (
            (('project', 'name'), True),
        )

class ConversationalDevelopmentIndexMetrics(BaseModel):
    created_at = DateTimeField()
    instance_boards = FloatField()
    instance_ci_pipelines = FloatField()
    instance_deployments = FloatField()
    instance_environments = FloatField()
    instance_issues = FloatField()
    instance_merge_requests = FloatField()
    instance_milestones = FloatField()
    instance_notes = FloatField()
    instance_projects_prometheus_active = FloatField()
    instance_service_desk_issues = FloatField()
    leader_boards = FloatField()
    leader_ci_pipelines = FloatField()
    leader_deployments = FloatField()
    leader_environments = FloatField()
    leader_issues = FloatField()
    leader_merge_requests = FloatField()
    leader_milestones = FloatField()
    leader_notes = FloatField()
    leader_projects_prometheus_active = FloatField()
    leader_service_desk_issues = FloatField()
    percentage_boards = FloatField()
    percentage_ci_pipelines = FloatField()
    percentage_deployments = FloatField()
    percentage_environments = FloatField()
    percentage_issues = FloatField()
    percentage_merge_requests = FloatField()
    percentage_milestones = FloatField()
    percentage_notes = FloatField()
    percentage_projects_prometheus_active = FloatField()
    percentage_service_desk_issues = FloatField()
    updated_at = DateTimeField()

    class Meta:
        db_table = 'conversational_development_index_metrics'

class DeployKeysProjects(BaseModel):
    can_push = BooleanField()
    created_at = DateTimeField(null=True)
    deploy_key = IntegerField(db_column='deploy_key_id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'deploy_keys_projects'

class DeployTokens(BaseModel):
    created_at = DateTimeField()
    expires_at = DateTimeField()
    name = CharField()
    read_registry = BooleanField()
    read_repository = BooleanField()
    revoked = BooleanField(null=True)
    token = CharField(unique=True)

    class Meta:
        db_table = 'deploy_tokens'
        indexes = (
            (('id', 'expires_at', 'token'), False),
        )

class Deployments(BaseModel):
    created_at = DateTimeField(index=True, null=True)
    deployable = IntegerField(db_column='deployable_id', null=True)
    deployable_type = CharField(null=True)
    environment = IntegerField(db_column='environment_id')
    iid = IntegerField()
    on_stop = CharField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    ref = CharField()
    sha = CharField()
    tag = BooleanField()
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', null=True)

    class Meta:
        db_table = 'deployments'
        indexes = (
            (('environment', 'project', 'iid'), False),
            (('id', 'environment'), False),
            (('iid', 'project'), True),
        )

class Emails(BaseModel):
    confirmation_sent_at = DateTimeField(null=True)
    confirmation_token = CharField(null=True, unique=True)
    confirmed_at = DateTimeField(null=True)
    created_at = DateTimeField(null=True)
    email = CharField(unique=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', index=True)

    class Meta:
        db_table = 'emails'

class Environments(BaseModel):
    created_at = DateTimeField(null=True)
    environment_type = CharField(null=True)
    external_url = CharField(null=True)
    name = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    slug = CharField()
    state = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'environments'
        indexes = (
            (('project', 'name'), True),
            (('project', 'slug'), True),
        )

class Issues(BaseModel):
    author = ForeignKeyField(db_column='author_id', null=True, rel_model=Users, to_field='id')
    cached_markdown_version = IntegerField(null=True)
    closed_at = DateTimeField(null=True)
    closed_by = ForeignKeyField(db_column='closed_by_id', null=True, rel_model=Users, related_name='users_closed_by_set', to_field='id')
    confidential = BooleanField(index=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    discussion_locked = BooleanField(null=True)
    due_date = DateField(null=True)
    iid = IntegerField(null=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by = IntegerField(db_column='last_edited_by_id', null=True)
    lock_version = IntegerField(null=True)
    milestone = ForeignKeyField(db_column='milestone_id', null=True, rel_model=Milestones, to_field='id')
    moved_to = ForeignKeyField(db_column='moved_to_id', null=True, rel_model='self', to_field='id')
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    relative_position = IntegerField(index=True, null=True)
    service_desk_reply_to = CharField(null=True)
    state = CharField(index=True, null=True)
    time_estimate = IntegerField(null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    updated_by = ForeignKeyField(db_column='updated_by_id', null=True, rel_model=Users, related_name='users_updated_by_set', to_field='id')
    weight = IntegerField(null=True)

    class Meta:
        db_table = 'issues'
        indexes = (
            (('project', 'id', 'created_at', 'state'), False),
            (('project', 'id', 'state', 'updated_at'), False),
            (('project', 'iid'), True),
            (('state', 'due_date', 'project', 'id'), False),
        )

class Epics(BaseModel):
    assignee = ForeignKeyField(db_column='assignee_id', null=True, rel_model=Users, to_field='id')
    author = ForeignKeyField(db_column='author_id', rel_model=Users, related_name='users_author_set', to_field='id')
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField(null=True)
    description_html = TextField(null=True)
    end_date = DateField(index=True, null=True)
    group = ForeignKeyField(db_column='group_id', rel_model=Namespaces, to_field='id')
    iid = IntegerField(index=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by = IntegerField(db_column='last_edited_by_id', null=True)
    lock_version = IntegerField(null=True)
    milestone = ForeignKeyField(db_column='milestone_id', null=True, rel_model=Milestones, to_field='id')
    start_date = DateField(index=True, null=True)
    title = CharField()
    title_html = CharField()
    updated_at = DateTimeField()
    updated_by = IntegerField(db_column='updated_by_id', null=True)

    class Meta:
        db_table = 'epics'

class EpicIssues(BaseModel):
    epic = ForeignKeyField(db_column='epic_id', rel_model=Epics, to_field='id')
    issue = ForeignKeyField(db_column='issue_id', rel_model=Issues, to_field='id', unique=True)
    relative_position = IntegerField()

    class Meta:
        db_table = 'epic_issues'

class EpicMetrics(BaseModel):
    created_at = DateTimeField()
    epic = ForeignKeyField(db_column='epic_id', rel_model=Epics, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'epic_metrics'

class Events(BaseModel):
    action = IntegerField(index=True)
    author = ForeignKeyField(db_column='author_id', rel_model=Users, to_field='id')
    created_at = DateTimeField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    target = IntegerField(db_column='target_id', null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'events'
        indexes = (
            (('project', 'author'), False),
            (('project', 'id'), False),
            (('target', 'target_type'), False),
        )

class FeatureGates(BaseModel):
    created_at = DateTimeField()
    feature_key = CharField()
    key = CharField()
    updated_at = DateTimeField()
    value = CharField(null=True)

    class Meta:
        db_table = 'feature_gates'
        indexes = (
            (('feature_key', 'key', 'value'), True),
        )

class Features(BaseModel):
    created_at = DateTimeField()
    key = CharField(unique=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'features'

class ForkNetworks(BaseModel):
    deleted_root_project_name = CharField(null=True)
    root_project = ForeignKeyField(db_column='root_project_id', null=True, rel_model=Projects, to_field='id', unique=True)

    class Meta:
        db_table = 'fork_networks'

class ForkNetworkMembers(BaseModel):
    fork_network = ForeignKeyField(db_column='fork_network_id', rel_model=ForkNetworks, to_field='id')
    forked_from_project = ForeignKeyField(db_column='forked_from_project_id', null=True, rel_model=Projects, to_field='id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, related_name='projects_project_set', to_field='id', unique=True)

    class Meta:
        db_table = 'fork_network_members'

class ForkedProjectLinks(BaseModel):
    created_at = DateTimeField(null=True)
    forked_from_project = IntegerField(db_column='forked_from_project_id')
    forked_to_project = ForeignKeyField(db_column='forked_to_project_id', rel_model=Projects, to_field='id', unique=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'forked_project_links'

class Services(BaseModel):
    active = BooleanField()
    category = CharField()
    commit_events = BooleanField()
    confidential_issues_events = BooleanField()
    confidential_note_events = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    default = BooleanField(null=True)
    issues_events = BooleanField(null=True)
    job_events = BooleanField()
    merge_requests_events = BooleanField(null=True)
    note_events = BooleanField()
    pipeline_events = BooleanField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    properties = TextField(null=True)
    push_events = BooleanField(null=True)
    tag_push_events = BooleanField(null=True)
    template = BooleanField(index=True, null=True)
    title = CharField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    wiki_page_events = BooleanField(null=True)

    class Meta:
        db_table = 'services'

class GcpClusters(BaseModel):
    ca_cert = TextField(null=True)
    created_at = DateTimeField()
    enabled = BooleanField(null=True)
    encrypted_gcp_token = TextField(null=True)
    encrypted_gcp_token_iv = CharField(null=True)
    encrypted_kubernetes_token = TextField(null=True)
    encrypted_kubernetes_token_iv = CharField(null=True)
    encrypted_password = TextField(null=True)
    encrypted_password_iv = CharField(null=True)
    endpoint = CharField(null=True)
    gcp_cluster_name = CharField()
    gcp_cluster_size = IntegerField()
    gcp_cluster_zone = CharField()
    gcp_machine_type = CharField(null=True)
    gcp_operation = CharField(db_column='gcp_operation_id', null=True)
    gcp_project = CharField(db_column='gcp_project_id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)
    project_namespace = CharField(null=True)
    service = ForeignKeyField(db_column='service_id', null=True, rel_model=Services, to_field='id')
    status = IntegerField(null=True)
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')
    username = CharField(null=True)

    class Meta:
        db_table = 'gcp_clusters'

class GeoRepositoryUpdatedEvents(BaseModel):
    branches_affected = IntegerField()
    id = BigIntegerField(primary_key=True)
    new_branch = BooleanField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    ref = TextField(null=True)
    remove_branch = BooleanField()
    source = IntegerField(index=True)
    tags_affected = IntegerField()

    class Meta:
        db_table = 'geo_repository_updated_events'

class GeoRepositoryDeletedEvents(BaseModel):
    deleted_path = TextField()
    deleted_project_name = TextField()
    deleted_wiki_path = TextField(null=True)
    id = BigIntegerField(primary_key=True)
    project = IntegerField(db_column='project_id', index=True)
    repository_storage_name = TextField()
    repository_storage_path = TextField()

    class Meta:
        db_table = 'geo_repository_deleted_events'

class GeoRepositoryRenamedEvents(BaseModel):
    id = BigIntegerField(primary_key=True)
    new_path = TextField()
    new_path_with_namespace = TextField()
    new_wiki_path_with_namespace = TextField()
    old_path = TextField()
    old_path_with_namespace = TextField()
    old_wiki_path_with_namespace = TextField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    repository_storage_name = TextField()
    repository_storage_path = TextField()

    class Meta:
        db_table = 'geo_repository_renamed_events'

class GeoNodes(BaseModel):
    access_key = CharField(index=True, null=True)
    clone_url_prefix = CharField(null=True)
    enabled = BooleanField()
    encrypted_secret_access_key = CharField(null=True)
    encrypted_secret_access_key_iv = CharField(null=True)
    files_max_capacity = IntegerField()
    oauth_application = IntegerField(db_column='oauth_application_id', null=True)
    primary = BooleanField(index=True, null=True)
    repos_max_capacity = IntegerField()
    selective_sync_shards = TextField(null=True)
    selective_sync_type = CharField(null=True)
    url = CharField(unique=True)

    class Meta:
        db_table = 'geo_nodes'

class GeoRepositoriesChangedEvents(BaseModel):
    geo_node = ForeignKeyField(db_column='geo_node_id', rel_model=GeoNodes, to_field='id')
    id = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'geo_repositories_changed_events'

class GeoRepositoryCreatedEvents(BaseModel):
    id = BigIntegerField(primary_key=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    project_name = TextField()
    repo_path = TextField()
    repository_storage_name = TextField()
    repository_storage_path = TextField()
    wiki_path = TextField(null=True)

    class Meta:
        db_table = 'geo_repository_created_events'

class GeoHashedStorageMigratedEvents(BaseModel):
    id = BigIntegerField(primary_key=True)
    new_disk_path = TextField()
    new_storage_version = IntegerField()
    new_wiki_disk_path = TextField()
    old_disk_path = TextField()
    old_storage_version = IntegerField(null=True)
    old_wiki_disk_path = TextField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    repository_storage_name = TextField()
    repository_storage_path = TextField()

    class Meta:
        db_table = 'geo_hashed_storage_migrated_events'

class GeoLfsObjectDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigIntegerField(primary_key=True)
    lfs_object = IntegerField(db_column='lfs_object_id', index=True)
    oid = CharField()

    class Meta:
        db_table = 'geo_lfs_object_deleted_events'

class GeoUploadDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigIntegerField(primary_key=True)
    model = IntegerField(db_column='model_id')
    model_type = CharField()
    upload = IntegerField(db_column='upload_id', index=True)
    uploader = CharField()

    class Meta:
        db_table = 'geo_upload_deleted_events'

class GeoJobArtifactDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigIntegerField(primary_key=True)
    job_artifact = IntegerField(db_column='job_artifact_id', index=True)

    class Meta:
        db_table = 'geo_job_artifact_deleted_events'

class GeoEventLog(BaseModel):
    created_at = DateTimeField()
    hashed_storage_attachments_event = BigIntegerField(db_column='hashed_storage_attachments_event_id', null=True)
    hashed_storage_migrated_event = ForeignKeyField(db_column='hashed_storage_migrated_event_id', null=True, rel_model=GeoHashedStorageMigratedEvents, to_field='id')
    id = BigIntegerField(primary_key=True)
    job_artifact_deleted_event = ForeignKeyField(db_column='job_artifact_deleted_event_id', null=True, rel_model=GeoJobArtifactDeletedEvents, to_field='id')
    lfs_object_deleted_event = ForeignKeyField(db_column='lfs_object_deleted_event_id', null=True, rel_model=GeoLfsObjectDeletedEvents, to_field='id')
    repositories_changed_event = ForeignKeyField(db_column='repositories_changed_event_id', null=True, rel_model=GeoRepositoriesChangedEvents, to_field='id')
    repository_created_event = ForeignKeyField(db_column='repository_created_event_id', null=True, rel_model=GeoRepositoryCreatedEvents, to_field='id')
    repository_deleted_event = ForeignKeyField(db_column='repository_deleted_event_id', null=True, rel_model=GeoRepositoryDeletedEvents, to_field='id')
    repository_renamed_event = ForeignKeyField(db_column='repository_renamed_event_id', null=True, rel_model=GeoRepositoryRenamedEvents, to_field='id')
    repository_updated_event = ForeignKeyField(db_column='repository_updated_event_id', null=True, rel_model=GeoRepositoryUpdatedEvents, to_field='id')
    upload_deleted_event = ForeignKeyField(db_column='upload_deleted_event_id', null=True, rel_model=GeoUploadDeletedEvents, to_field='id')

    class Meta:
        db_table = 'geo_event_log'

class GeoHashedStorageAttachmentsEvents(BaseModel):
    id = BigIntegerField(primary_key=True)
    new_attachments_path = TextField()
    old_attachments_path = TextField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')

    class Meta:
        db_table = 'geo_hashed_storage_attachments_events'

class GeoNodeNamespaceLinks(BaseModel):
    created_at = DateTimeField()
    geo_node = ForeignKeyField(db_column='geo_node_id', rel_model=GeoNodes, to_field='id')
    namespace = ForeignKeyField(db_column='namespace_id', rel_model=Namespaces, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'geo_node_namespace_links'
        indexes = (
            (('geo_node', 'namespace'), True),
        )

class GeoNodeStatuses(BaseModel):
    attachments_count = IntegerField(null=True)
    attachments_failed_count = IntegerField(null=True)
    attachments_synced_count = IntegerField(null=True)
    attachments_synced_missing_on_primary_count = IntegerField(null=True)
    created_at = DateTimeField()
    cursor_last_event_date = DateTimeField(null=True)
    cursor_last_event = IntegerField(db_column='cursor_last_event_id', null=True)
    db_replication_lag_seconds = IntegerField(null=True)
    geo_node = ForeignKeyField(db_column='geo_node_id', rel_model=GeoNodes, to_field='id', unique=True)
    job_artifacts_count = IntegerField(null=True)
    job_artifacts_failed_count = IntegerField(null=True)
    job_artifacts_synced_count = IntegerField(null=True)
    job_artifacts_synced_missing_on_primary_count = IntegerField(null=True)
    last_event_date = DateTimeField(null=True)
    last_event = IntegerField(db_column='last_event_id', null=True)
    last_successful_status_check_at = DateTimeField(null=True)
    lfs_objects_count = IntegerField(null=True)
    lfs_objects_failed_count = IntegerField(null=True)
    lfs_objects_synced_count = IntegerField(null=True)
    lfs_objects_synced_missing_on_primary_count = IntegerField(null=True)
    replication_slots_count = IntegerField(null=True)
    replication_slots_max_retained_wal_bytes = BigIntegerField(null=True)
    replication_slots_used_count = IntegerField(null=True)
    repositories_count = IntegerField(null=True)
    repositories_failed_count = IntegerField(null=True)
    repositories_synced_count = IntegerField(null=True)
    repositories_verification_failed_count = IntegerField(null=True)
    repositories_verified_count = IntegerField(null=True)
    revision = CharField(null=True)
    status_message = CharField(null=True)
    updated_at = DateTimeField()
    version = CharField(null=True)
    wikis_count = IntegerField(null=True)
    wikis_failed_count = IntegerField(null=True)
    wikis_synced_count = IntegerField(null=True)
    wikis_verification_failed_count = IntegerField(null=True)
    wikis_verified_count = IntegerField(null=True)

    class Meta:
        db_table = 'geo_node_statuses'

class GpgKeys(BaseModel):
    created_at = DateTimeField()
    fingerprint = BlobField(null=True, unique=True)
    key = TextField(null=True)
    primary_keyid = BlobField(null=True, unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'gpg_keys'

class GpgKeySubkeys(BaseModel):
    fingerprint = BlobField(null=True, unique=True)
    gpg_key = ForeignKeyField(db_column='gpg_key_id', rel_model=GpgKeys, to_field='id')
    keyid = BlobField(null=True, unique=True)

    class Meta:
        db_table = 'gpg_key_subkeys'

class GpgSignatures(BaseModel):
    commit_sha = BlobField(null=True, unique=True)
    created_at = DateTimeField()
    gpg_key = ForeignKeyField(db_column='gpg_key_id', null=True, rel_model=GpgKeys, to_field='id')
    gpg_key_primary_keyid = BlobField(index=True, null=True)
    gpg_key_subkey = ForeignKeyField(db_column='gpg_key_subkey_id', null=True, rel_model=GpgKeySubkeys, to_field='id')
    gpg_key_user_email = TextField(null=True)
    gpg_key_user_name = TextField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    updated_at = DateTimeField()
    verification_status = IntegerField()

    class Meta:
        db_table = 'gpg_signatures'

class GroupCustomAttributes(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', rel_model=Namespaces, to_field='id')
    key = CharField()
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        db_table = 'group_custom_attributes'
        indexes = (
            (('group', 'key'), True),
            (('key', 'value'), False),
        )

class HistoricalData(BaseModel):
    active_user_count = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    date = DateField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'historical_data'

class Identities(BaseModel):
    created_at = DateTimeField(null=True)
    extern_uid = CharField(null=True)
    provider = CharField(null=True)
    secondary_extern_uid = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', index=True, null=True)

    class Meta:
        db_table = 'identities'

class IndexStatuses(BaseModel):
    created_at = DateTimeField()
    indexed_at = DateTimeField(null=True)
    last_commit = CharField(null=True)
    note = TextField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'index_statuses'

class InternalIds(BaseModel):
    id = BigIntegerField(primary_key=True)
    last_value = IntegerField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    usage = IntegerField()

    class Meta:
        db_table = 'internal_ids'
        indexes = (
            (('project', 'usage'), True),
        )

class IssueAssignees(BaseModel):
    issue = ForeignKeyField(db_column='issue_id', rel_model=Issues, to_field='id')
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')

    class Meta:
        db_table = 'issue_assignees'
        indexes = (
            (('user', 'issue'), True),
        )

class IssueLinks(BaseModel):
    created_at = DateTimeField(null=True)
    source = ForeignKeyField(db_column='source_id', rel_model=Issues, to_field='id')
    target = ForeignKeyField(db_column='target_id', rel_model=Issues, related_name='issues_target_set', to_field='id')
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'issue_links'
        indexes = (
            (('source', 'target'), True),
        )

class IssueMetrics(BaseModel):
    created_at = DateTimeField()
    first_added_to_board_at = DateTimeField(null=True)
    first_associated_with_milestone_at = DateTimeField(null=True)
    first_mentioned_in_commit_at = DateTimeField(null=True)
    issue = ForeignKeyField(db_column='issue_id', rel_model=Issues, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'issue_metrics'

class Keys(BaseModel):
    created_at = DateTimeField(null=True)
    fingerprint = CharField(null=True, unique=True)
    key = TextField(null=True)
    last_used_at = DateTimeField(null=True)
    public = BooleanField()
    title = CharField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', index=True, null=True)

    class Meta:
        db_table = 'keys'

class LabelLinks(BaseModel):
    created_at = DateTimeField(null=True)
    label = IntegerField(db_column='label_id', index=True, null=True)
    target = IntegerField(db_column='target_id', null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'label_links'
        indexes = (
            (('target', 'target_type'), False),
        )

class LabelPriorities(BaseModel):
    created_at = DateTimeField()
    label = ForeignKeyField(db_column='label_id', rel_model=Labels, to_field='id')
    priority = IntegerField(index=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'label_priorities'
        indexes = (
            (('project', 'label'), True),
        )

class LdapGroupLinks(BaseModel):
    cn = CharField(null=True)
    created_at = DateTimeField(null=True)
    filter = CharField(null=True)
    group_access = IntegerField()
    group = IntegerField(db_column='group_id')
    provider = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'ldap_group_links'

class LfsFileLocks(BaseModel):
    created_at = DateTimeField()
    path = CharField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')

    class Meta:
        db_table = 'lfs_file_locks'
        indexes = (
            (('project', 'path'), True),
        )

class LfsObjects(BaseModel):
    created_at = DateTimeField(null=True)
    file = CharField(null=True)
    file_store = IntegerField(null=True)
    oid = CharField(unique=True)
    size = BigIntegerField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'lfs_objects'

class LfsObjectsProjects(BaseModel):
    created_at = DateTimeField(null=True)
    lfs_object = IntegerField(db_column='lfs_object_id')
    project = IntegerField(db_column='project_id', index=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'lfs_objects_projects'

class Licenses(BaseModel):
    created_at = DateTimeField(null=True)
    data = TextField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'licenses'

class Lists(BaseModel):
    board = ForeignKeyField(db_column='board_id', rel_model=Boards, to_field='id')
    created_at = DateTimeField()
    label = ForeignKeyField(db_column='label_id', null=True, rel_model=Labels, to_field='id')
    list_type = IntegerField()
    position = IntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'lists'
        indexes = (
            (('board', 'label'), True),
        )

class Members(BaseModel):
    access_level = IntegerField(index=True)
    created_at = DateTimeField(null=True)
    created_by = IntegerField(db_column='created_by_id', null=True)
    expires_at = DateField(null=True)
    invite_accepted_at = DateTimeField(null=True)
    invite_email = CharField(null=True)
    invite_token = CharField(null=True, unique=True)
    ldap = BooleanField()
    notification_level = IntegerField()
    override = BooleanField()
    requested_at = DateTimeField(index=True, null=True)
    source = IntegerField(db_column='source_id')
    source_type = CharField()
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'members'
        indexes = (
            (('source_type', 'source'), False),
        )

class MergeRequestDiffCommits(BaseModel):
    author_email = TextField(null=True)
    author_name = TextField(null=True)
    authored_date = DateTimeField(null=True)
    committed_date = DateTimeField(null=True)
    committer_email = TextField(null=True)
    committer_name = TextField(null=True)
    merge_request_diff = ForeignKeyField(db_column='merge_request_diff_id', rel_model=MergeRequestDiffs, to_field='id')
    message = TextField(null=True)
    relative_order = IntegerField()
    sha = BlobField(index=True)

    class Meta:
        db_table = 'merge_request_diff_commits'
        indexes = (
            (('merge_request_diff', 'relative_order'), True),
        )

class MergeRequestDiffFiles(BaseModel):
    a_mode = CharField()
    b_mode = CharField()
    binary = BooleanField(null=True)
    deleted_file = BooleanField()
    diff = TextField()
    merge_request_diff = ForeignKeyField(db_column='merge_request_diff_id', rel_model=MergeRequestDiffs, to_field='id')
    new_file = BooleanField()
    new_path = TextField()
    old_path = TextField()
    relative_order = IntegerField()
    renamed_file = BooleanField()
    too_large = BooleanField()

    class Meta:
        db_table = 'merge_request_diff_files'
        indexes = (
            (('merge_request_diff', 'relative_order'), True),
        )

class MergeRequestMetrics(BaseModel):
    created_at = DateTimeField()
    first_deployed_to_production_at = DateTimeField(index=True, null=True)
    latest_build_finished_at = DateTimeField(null=True)
    latest_build_started_at = DateTimeField(null=True)
    latest_closed_at = DateTimeField(null=True)
    latest_closed_by = ForeignKeyField(db_column='latest_closed_by_id', null=True, rel_model=Users, to_field='id')
    merge_request = ForeignKeyField(db_column='merge_request_id', rel_model=MergeRequests, to_field='id')
    merged_at = DateTimeField(null=True)
    merged_by = ForeignKeyField(db_column='merged_by_id', null=True, rel_model=Users, related_name='users_merged_by_set', to_field='id')
    pipeline = ForeignKeyField(db_column='pipeline_id', null=True, rel_model=CiPipelines, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'merge_request_metrics'

class MergeRequestsClosingIssues(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(db_column='issue_id', rel_model=Issues, to_field='id')
    merge_request = ForeignKeyField(db_column='merge_request_id', rel_model=MergeRequests, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'merge_requests_closing_issues'

class NamespaceStatistics(BaseModel):
    namespace = ForeignKeyField(db_column='namespace_id', rel_model=Namespaces, to_field='id', unique=True)
    shared_runners_seconds = IntegerField()
    shared_runners_seconds_last_reset = DateTimeField(null=True)

    class Meta:
        db_table = 'namespace_statistics'

class Notes(BaseModel):
    attachment = CharField(null=True)
    author = IntegerField(db_column='author_id', index=True, null=True)
    cached_markdown_version = IntegerField(null=True)
    change_position = TextField(null=True)
    commit = CharField(db_column='commit_id', index=True, null=True)
    created_at = DateTimeField(index=True, null=True)
    discussion = CharField(db_column='discussion_id', index=True, null=True)
    line_code = CharField(index=True, null=True)
    note = TextField(index=True, null=True)
    note_html = TextField(null=True)
    noteable = IntegerField(db_column='noteable_id', null=True)
    noteable_type = CharField(index=True, null=True)
    original_position = TextField(null=True)
    position = TextField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    resolved_at = DateTimeField(null=True)
    resolved_by = IntegerField(db_column='resolved_by_id', null=True)
    resolved_by_push = BooleanField(null=True)
    st_diff = TextField(null=True)
    system = BooleanField()
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    updated_by = IntegerField(db_column='updated_by_id', null=True)

    class Meta:
        db_table = 'notes'
        indexes = (
            (('noteable', 'noteable_type'), False),
            (('project', 'noteable_type'), False),
        )

class NotificationSettings(BaseModel):
    close_issue = BooleanField(null=True)
    close_merge_request = BooleanField(null=True)
    created_at = DateTimeField()
    failed_pipeline = BooleanField(null=True)
    level = IntegerField()
    merge_merge_request = BooleanField(null=True)
    new_issue = BooleanField(null=True)
    new_merge_request = BooleanField(null=True)
    new_note = BooleanField(null=True)
    push_to_merge_request = BooleanField(null=True)
    reassign_issue = BooleanField(null=True)
    reassign_merge_request = BooleanField(null=True)
    reopen_issue = BooleanField(null=True)
    reopen_merge_request = BooleanField(null=True)
    source = IntegerField(db_column='source_id', null=True)
    source_type = CharField(null=True)
    success_pipeline = BooleanField(null=True)
    updated_at = DateTimeField()
    user = IntegerField(db_column='user_id', index=True)

    class Meta:
        db_table = 'notification_settings'
        indexes = (
            (('source', 'source_type'), False),
            (('source', 'source_type', 'user'), True),
        )

class OauthAccessGrants(BaseModel):
    application = IntegerField(db_column='application_id')
    created_at = DateTimeField()
    expires_in = IntegerField()
    redirect_uri = TextField()
    resource_owner = IntegerField(db_column='resource_owner_id')
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        db_table = 'oauth_access_grants'

class OauthAccessTokens(BaseModel):
    application = IntegerField(db_column='application_id', null=True)
    created_at = DateTimeField()
    expires_in = IntegerField(null=True)
    refresh_token = CharField(null=True, unique=True)
    resource_owner = IntegerField(db_column='resource_owner_id', index=True, null=True)
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        db_table = 'oauth_access_tokens'

class OauthApplications(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField()
    owner = IntegerField(db_column='owner_id', null=True)
    owner_type = CharField(null=True)
    redirect_uri = TextField()
    scopes = CharField()
    secret = CharField()
    trusted = BooleanField()
    uid = CharField(unique=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'oauth_applications'
        indexes = (
            (('owner', 'owner_type'), False),
        )

class OauthOpenidRequests(BaseModel):
    access_grant = ForeignKeyField(db_column='access_grant_id', rel_model=OauthAccessGrants, to_field='id')
    nonce = CharField()

    class Meta:
        db_table = 'oauth_openid_requests'

class PagesDomains(BaseModel):
    certificate = TextField(null=True)
    domain = CharField(null=True, unique=True)
    enabled_until = DateTimeField(null=True)
    encrypted_key = TextField(null=True)
    encrypted_key_iv = CharField(null=True)
    encrypted_key_salt = CharField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    verification_code = CharField()
    verified_at = DateTimeField(index=True, null=True)

    class Meta:
        db_table = 'pages_domains'
        indexes = (
            (('project', 'enabled_until'), False),
            (('verified_at', 'enabled_until'), False),
        )

class PathLocks(BaseModel):
    created_at = DateTimeField()
    path = CharField(index=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'path_locks'

class PersonalAccessTokens(BaseModel):
    created_at = DateTimeField()
    expires_at = DateField(null=True)
    impersonation = BooleanField()
    name = CharField()
    revoked = BooleanField(null=True)
    scopes = CharField()
    token = CharField(unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')

    class Meta:
        db_table = 'personal_access_tokens'

class ProjectAuthorizations(BaseModel):
    access_level = IntegerField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'project_authorizations'
        indexes = (
            (('user', 'project', 'access_level'), True),
        )

class ProjectAutoDevops(BaseModel):
    created_at = DateTimeField()
    domain = CharField(null=True)
    enabled = BooleanField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'project_auto_devops'

class ProjectCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        db_table = 'project_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('project', 'key'), True),
        )

class ProjectDeployTokens(BaseModel):
    created_at = DateTimeField()
    deploy_token = ForeignKeyField(db_column='deploy_token_id', rel_model=DeployTokens, to_field='id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')

    class Meta:
        db_table = 'project_deploy_tokens'
        indexes = (
            (('project', 'deploy_token'), True),
        )

class ProjectFeatures(BaseModel):
    builds_access_level = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    issues_access_level = IntegerField(null=True)
    merge_requests_access_level = IntegerField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    repository_access_level = IntegerField()
    snippets_access_level = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    wiki_access_level = IntegerField(null=True)

    class Meta:
        db_table = 'project_features'

class ProjectGroupLinks(BaseModel):
    created_at = DateTimeField(null=True)
    expires_at = DateField(null=True)
    group_access = IntegerField()
    group = IntegerField(db_column='group_id', index=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'project_group_links'

class ProjectImportData(BaseModel):
    data = TextField(null=True)
    encrypted_credentials = TextField(null=True)
    encrypted_credentials_iv = CharField(null=True)
    encrypted_credentials_salt = CharField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')

    class Meta:
        db_table = 'project_import_data'

class ProjectMirrorData(BaseModel):
    created_at = DateTimeField(null=True)
    last_update_scheduled_at = DateTimeField(null=True)
    last_update_started_at = DateTimeField(null=True)
    next_execution_timestamp = DateTimeField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id', unique=True)
    retry_count = IntegerField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'project_mirror_data'
        indexes = (
            (('retry_count', 'next_execution_timestamp'), False),
        )

class ProjectRepositoryStates(BaseModel):
    last_repository_verification_failure = CharField(index=True, null=True)
    last_wiki_verification_failure = CharField(index=True, null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)
    repository_verification_checksum = BlobField(null=True)
    wiki_verification_checksum = BlobField(null=True)

    class Meta:
        db_table = 'project_repository_states'
        indexes = (
            (('repository_verification_checksum', 'wiki_verification_checksum'), False),
        )

class ProjectStatistics(BaseModel):
    build_artifacts_size = BigIntegerField()
    commit_count = BigIntegerField()
    lfs_objects_size = BigIntegerField()
    namespace = IntegerField(db_column='namespace_id', index=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)
    repository_size = BigIntegerField()
    shared_runners_seconds = BigIntegerField()
    shared_runners_seconds_last_reset = DateTimeField(null=True)
    storage_size = BigIntegerField()

    class Meta:
        db_table = 'project_statistics'

class PrometheusMetrics(BaseModel):
    created_at = DateTimeField()
    group = IntegerField(index=True)
    legend = CharField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    query = CharField()
    title = CharField()
    unit = CharField(null=True)
    updated_at = DateTimeField()
    y_label = CharField(null=True)

    class Meta:
        db_table = 'prometheus_metrics'

class ProtectedBranches(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'protected_branches'

class ProtectedBranchMergeAccessLevels(BaseModel):
    access_level = IntegerField(null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    protected_branch = ForeignKeyField(db_column='protected_branch_id', rel_model=ProtectedBranches, to_field='id')
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'protected_branch_merge_access_levels'

class ProtectedBranchPushAccessLevels(BaseModel):
    access_level = IntegerField(null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    protected_branch = ForeignKeyField(db_column='protected_branch_id', rel_model=ProtectedBranches, to_field='id')
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'protected_branch_push_access_levels'

class ProtectedBranchUnprotectAccessLevels(BaseModel):
    access_level = IntegerField(null=True)
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    protected_branch = ForeignKeyField(db_column='protected_branch_id', rel_model=ProtectedBranches, to_field='id')
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'protected_branch_unprotect_access_levels'

class ProtectedTags(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField()

    class Meta:
        db_table = 'protected_tags'

class ProtectedTagCreateAccessLevels(BaseModel):
    access_level = IntegerField(null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(db_column='group_id', null=True, rel_model=Namespaces, to_field='id')
    protected_tag = ForeignKeyField(db_column='protected_tag_id', rel_model=ProtectedTags, to_field='id')
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'protected_tag_create_access_levels'

class PushEventPayloads(BaseModel):
    action = IntegerField()
    commit_count = BigIntegerField()
    commit_from = BlobField(null=True)
    commit_title = CharField(null=True)
    commit_to = BlobField(null=True)
    event = ForeignKeyField(db_column='event_id', rel_model=Events, to_field='id', unique=True)
    ref = TextField(null=True)
    ref_type = IntegerField()

    class Meta:
        db_table = 'push_event_payloads'

class PushRules(BaseModel):
    author_email_regex = CharField(null=True)
    branch_name_regex = CharField(null=True)
    commit_committer_check = BooleanField(null=True)
    commit_message_regex = CharField(null=True)
    created_at = DateTimeField(null=True)
    delete_branch_regex = CharField(null=True)
    deny_delete_tag = BooleanField(null=True)
    file_name_regex = CharField(null=True)
    force_push_regex = CharField(null=True)
    is_sample = BooleanField(index=True, null=True)
    max_file_size = IntegerField()
    member_check = BooleanField()
    prevent_secrets = BooleanField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    regexp_uses_re2 = BooleanField(null=True)
    reject_unsigned_commits = BooleanField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'push_rules'

class RedirectRoutes(BaseModel):
    created_at = DateTimeField()
    path = CharField(unique=True)
    source = IntegerField(db_column='source_id')
    source_type = CharField()
    updated_at = DateTimeField()

    class Meta:
        db_table = 'redirect_routes'
        indexes = (
            (('source', 'source_type'), False),
        )

class Releases(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(null=True)
    description_html = TextField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    tag = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'releases'
        indexes = (
            (('tag', 'project'), False),
        )

class RemoteMirrors(BaseModel):
    created_at = DateTimeField()
    enabled = BooleanField(null=True)
    encrypted_credentials = TextField(null=True)
    encrypted_credentials_iv = CharField(null=True)
    encrypted_credentials_salt = CharField(null=True)
    last_error = CharField(null=True)
    last_successful_update_at = DateTimeField(index=True, null=True)
    last_update_at = DateTimeField(null=True)
    last_update_started_at = DateTimeField(null=True)
    only_protected_branches = BooleanField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    remote_name = CharField(null=True)
    update_status = CharField(null=True)
    updated_at = DateTimeField()
    url = CharField(null=True)

    class Meta:
        db_table = 'remote_mirrors'

class Routes(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField(null=True)
    path = CharField(index=True)
    source = IntegerField(db_column='source_id')
    source_type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = 'routes'
        indexes = (
            (('source', 'source_type'), True),
        )

class SamlProviders(BaseModel):
    certificate_fingerprint = CharField()
    enabled = BooleanField()
    group = ForeignKeyField(db_column='group_id', rel_model=Namespaces, to_field='id')
    sso_url = CharField()

    class Meta:
        db_table = 'saml_providers'

class SchemaMigrations(BaseModel):
    version = CharField(unique=True)

    class Meta:
        db_table = 'schema_migrations'

class SentNotifications(BaseModel):
    commit = CharField(db_column='commit_id', null=True)
    in_reply_to_discussion = CharField(db_column='in_reply_to_discussion_id', null=True)
    line_code = CharField(null=True)
    note_type = CharField(null=True)
    noteable = IntegerField(db_column='noteable_id', null=True)
    noteable_type = CharField(null=True)
    position = TextField(null=True)
    project = IntegerField(db_column='project_id', null=True)
    recipient = IntegerField(db_column='recipient_id', null=True)
    reply_key = CharField(unique=True)

    class Meta:
        db_table = 'sent_notifications'

class SlackIntegrations(BaseModel):
    alias = CharField()
    created_at = DateTimeField()
    service = ForeignKeyField(db_column='service_id', rel_model=Services, to_field='id')
    team = CharField(db_column='team_id')
    team_name = CharField()
    updated_at = DateTimeField()
    user = CharField(db_column='user_id')

    class Meta:
        db_table = 'slack_integrations'
        indexes = (
            (('team', 'alias'), True),
        )

class Snippets(BaseModel):
    author = IntegerField(db_column='author_id', index=True)
    cached_markdown_version = IntegerField(null=True)
    content = TextField(null=True)
    content_html = TextField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(null=True)
    description_html = TextField(null=True)
    file_name = CharField(index=True, null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    visibility_level = IntegerField(index=True)

    class Meta:
        db_table = 'snippets'

class SpamLogs(BaseModel):
    created_at = DateTimeField()
    description = TextField(null=True)
    noteable_type = CharField(null=True)
    recaptcha_verified = BooleanField()
    source_ip = CharField(null=True)
    submitted_as_ham = BooleanField()
    title = CharField(null=True)
    updated_at = DateTimeField()
    user_agent = CharField(null=True)
    user = IntegerField(db_column='user_id', null=True)
    via_api = BooleanField(null=True)

    class Meta:
        db_table = 'spam_logs'

class Subscriptions(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    subscribable = IntegerField(db_column='subscribable_id', null=True)
    subscribable_type = CharField(null=True)
    subscribed = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id', null=True)

    class Meta:
        db_table = 'subscriptions'
        indexes = (
            (('user', 'subscribable', 'subscribable_type', 'project'), True),
        )

class SystemNoteMetadata(BaseModel):
    action = CharField(null=True)
    commit_count = IntegerField(null=True)
    created_at = DateTimeField()
    note = ForeignKeyField(db_column='note_id', rel_model=Notes, to_field='id', unique=True)
    updated_at = DateTimeField()

    class Meta:
        db_table = 'system_note_metadata'

class Taggings(BaseModel):
    context = CharField(null=True)
    created_at = DateTimeField(null=True)
    tag = IntegerField(db_column='tag_id', index=True, null=True)
    taggable = IntegerField(db_column='taggable_id', null=True)
    taggable_type = CharField(null=True)
    tagger = IntegerField(db_column='tagger_id', null=True)
    tagger_type = CharField(null=True)

    class Meta:
        db_table = 'taggings'
        indexes = (
            (('taggable', 'taggable_type', 'context'), False),
            (('taggable_type', 'taggable'), False),
            (('tagger', 'context', 'tagger_type', 'tag', 'taggable', 'taggable_type'), True),
        )

class Tags(BaseModel):
    name = CharField(null=True, unique=True)
    taggings_count = IntegerField(null=True)

    class Meta:
        db_table = 'tags'

class Timelogs(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(db_column='issue_id', null=True, rel_model=Issues, to_field='id')
    merge_request = ForeignKeyField(db_column='merge_request_id', null=True, rel_model=MergeRequests, to_field='id')
    spent_at = DateTimeField(null=True)
    time_spent = IntegerField()
    updated_at = DateTimeField()
    user = IntegerField(db_column='user_id', index=True, null=True)

    class Meta:
        db_table = 'timelogs'

class Todos(BaseModel):
    action = IntegerField()
    author = ForeignKeyField(db_column='author_id', rel_model=Users, to_field='id')
    commit = CharField(db_column='commit_id', index=True, null=True)
    created_at = DateTimeField(null=True)
    note = ForeignKeyField(db_column='note_id', null=True, rel_model=Notes, to_field='id')
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    state = CharField()
    target = IntegerField(db_column='target_id', null=True)
    target_type = CharField()
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(db_column='user_id', rel_model=Users, related_name='users_user_set', to_field='id')

    class Meta:
        db_table = 'todos'
        indexes = (
            (('id', 'user'), False),
            (('target_type', 'target'), False),
            (('user', 'id'), False),
        )

class TrendingProjects(BaseModel):
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id', unique=True)

    class Meta:
        db_table = 'trending_projects'

class U2FRegistrations(BaseModel):
    certificate = TextField(null=True)
    counter = IntegerField(null=True)
    created_at = DateTimeField()
    key_handle = CharField(index=True, null=True)
    name = CharField(null=True)
    public_key = CharField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', null=True, rel_model=Users, to_field='id')

    class Meta:
        db_table = 'u2f_registrations'

class UntrackedFilesForUploads(BaseModel):
    path = CharField(unique=True)

    class Meta:
        db_table = 'untracked_files_for_uploads'

class Uploads(BaseModel):
    checksum = CharField(index=True, null=True)
    created_at = DateTimeField()
    model = IntegerField(db_column='model_id', null=True)
    model_type = CharField(null=True)
    mount_point = CharField(null=True)
    path = CharField()
    secret = CharField(null=True)
    size = BigIntegerField()
    store = IntegerField(null=True)
    uploader = CharField()

    class Meta:
        db_table = 'uploads'
        indexes = (
            (('model', 'model_type'), False),
            (('path', 'uploader'), False),
        )

class UserAgentDetails(BaseModel):
    created_at = DateTimeField()
    ip_address = CharField()
    subject = IntegerField(db_column='subject_id')
    subject_type = CharField()
    submitted = BooleanField()
    updated_at = DateTimeField()
    user_agent = CharField()

    class Meta:
        db_table = 'user_agent_details'
        indexes = (
            (('subject', 'subject_type'), False),
        )

class UserCallouts(BaseModel):
    feature_name = IntegerField()
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')

    class Meta:
        db_table = 'user_callouts'
        indexes = (
            (('feature_name', 'user'), True),
        )

class UserCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    updated_at = DateTimeField()
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')
    value = CharField()

    class Meta:
        db_table = 'user_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('user', 'key'), True),
        )

class UserInteractedProjects(BaseModel):
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id')

    class Meta:
        db_table = 'user_interacted_projects'
        indexes = (
            (('user', 'project'), True),
        )

class UserSyncedAttributesMetadata(BaseModel):
    email_synced = BooleanField(null=True)
    location_synced = BooleanField(null=True)
    name_synced = BooleanField(null=True)
    provider = CharField(null=True)
    user = ForeignKeyField(db_column='user_id', rel_model=Users, to_field='id', unique=True)

    class Meta:
        db_table = 'user_synced_attributes_metadata'

class UsersStarProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(db_column='project_id', rel_model=Projects, to_field='id')
    updated_at = DateTimeField(null=True)
    user = IntegerField(db_column='user_id')

    class Meta:
        db_table = 'users_star_projects'
        indexes = (
            (('project', 'user'), True),
        )

class WebHooks(BaseModel):
    confidential_issues_events = BooleanField()
    confidential_note_events = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    enable_ssl_verification = BooleanField(null=True)
    group = IntegerField(db_column='group_id', null=True)
    issues_events = BooleanField()
    job_events = BooleanField()
    merge_requests_events = BooleanField()
    note_events = BooleanField()
    pipeline_events = BooleanField()
    project = ForeignKeyField(db_column='project_id', null=True, rel_model=Projects, to_field='id')
    push_events = BooleanField()
    repository_update_events = BooleanField()
    service = IntegerField(db_column='service_id', null=True)
    tag_push_events = BooleanField(null=True)
    token = CharField(null=True)
    type = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    url = CharField(null=True)
    wiki_page_events = BooleanField()

    class Meta:
        db_table = 'web_hooks'

class WebHookLogs(BaseModel):
    created_at = DateTimeField()
    execution_duration = FloatField(null=True)
    internal_error_message = CharField(null=True)
    request_data = TextField(null=True)
    request_headers = TextField(null=True)
    response_body = TextField(null=True)
    response_headers = TextField(null=True)
    response_status = CharField(null=True)
    trigger = CharField(null=True)
    updated_at = DateTimeField()
    url = CharField(null=True)
    web_hook = ForeignKeyField(db_column='web_hook_id', rel_model=WebHooks, to_field='id')

    class Meta:
        db_table = 'web_hook_logs'

