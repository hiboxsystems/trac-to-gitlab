from peewee import *

database_proxy = Proxy()

class UnknownField(object):
    def __init__(self, *_, **__): pass

class BaseModel(Model):
    class Meta:
        database = database_proxy

class AbuseReports(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    message = TextField(null=True)
    message_html = TextField(null=True)
    reporter = IntegerField(column_name='reporter_id', null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', null=True)

    class Meta:
        table_name = 'abuse_reports'

class Appearances(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField()
    description_html = TextField(null=True)
    header_logo = CharField(null=True)
    logo = CharField(null=True)
    new_project_guidelines = TextField(null=True)
    new_project_guidelines_html = TextField(null=True)
    title = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'appearances'

class ApplicationSettings(BaseModel):
    admin_notification_email = CharField(null=True)
    after_sign_out_path = CharField(null=True)
    after_sign_up_text = TextField(null=True)
    after_sign_up_text_html = TextField(null=True)
    akismet_api_key = CharField(null=True)
    akismet_enabled = BooleanField(null=True)
    allow_local_requests_from_hooks_and_services = BooleanField()
    authorized_keys_enabled = BooleanField()
    auto_devops_domain = CharField(null=True)
    auto_devops_enabled = BooleanField()
    cached_markdown_version = IntegerField(null=True)
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
    email_author_in_body = BooleanField(null=True)
    enabled_git_access_protocol = CharField(null=True)
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
    pages_domain_verification_enabled = BooleanField()
    password_authentication_enabled_for_git = BooleanField()
    password_authentication_enabled_for_web = BooleanField(null=True)
    performance_bar_allowed_group = IntegerField(column_name='performance_bar_allowed_group_id', null=True)
    plantuml_enabled = BooleanField(null=True)
    plantuml_url = CharField(null=True)
    polling_interval_multiplier = DecimalField()
    project_export_enabled = BooleanField()
    prometheus_metrics_enabled = BooleanField()
    recaptcha_enabled = BooleanField(null=True)
    recaptcha_private_key = CharField(null=True)
    recaptcha_site_key = CharField(null=True)
    repository_checks_enabled = BooleanField(null=True)
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
    shared_runners_text = TextField(null=True)
    shared_runners_text_html = TextField(null=True)
    sidekiq_throttling_enabled = BooleanField(null=True)
    sidekiq_throttling_factor = DecimalField(null=True)
    sidekiq_throttling_queues = CharField(null=True)
    sign_in_text = TextField(null=True)
    sign_in_text_html = TextField(null=True)
    signup_enabled = BooleanField(null=True)
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
        table_name = 'application_settings'

class AuditEvents(BaseModel):
    author = IntegerField(column_name='author_id')
    created_at = DateTimeField(null=True)
    details = TextField(null=True)
    entity = IntegerField(column_name='entity_id')
    entity_type = CharField()
    type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'audit_events'
        indexes = (
            (('entity', 'entity_type'), False),
        )

class AwardEmoji(BaseModel):
    awardable = IntegerField(column_name='awardable_id', null=True)
    awardable_type = CharField(null=True)
    created_at = DateTimeField(null=True)
    name = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', null=True)

    class Meta:
        table_name = 'award_emoji'
        indexes = (
            (('awardable', 'awardable_type'), False),
            (('name', 'user'), False),
        )

class Namespaces(BaseModel):
    avatar = CharField(null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    description = CharField()
    description_html = TextField(null=True)
    lfs_enabled = BooleanField(null=True)
    name = CharField(index=True)
    owner = IntegerField(column_name='owner_id', index=True, null=True)
    parent = IntegerField(column_name='parent_id', null=True)
    path = CharField(index=True)
    request_access_enabled = BooleanField()
    require_two_factor_authentication = BooleanField(index=True)
    share_with_group_lock = BooleanField(null=True)
    two_factor_grace_period = IntegerField()
    type = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField()

    class Meta:
        table_name = 'namespaces'
        indexes = (
            (('id', 'parent'), True),
            (('parent', 'name'), True),
        )

class Projects(BaseModel):
    archived = BooleanField()
    auto_cancel_pending_pipelines = IntegerField()
    avatar = CharField(null=True)
    build_allow_git_fetch = BooleanField()
    build_coverage_regex = CharField(null=True)
    build_timeout = IntegerField()
    cached_markdown_version = IntegerField(null=True)
    ci_config_path = CharField(null=True)
    ci = IntegerField(column_name='ci_id', index=True, null=True)
    container_registry_enabled = BooleanField(null=True)
    created_at = DateTimeField(index=True, null=True)
    creator = IntegerField(column_name='creator_id', index=True, null=True)
    delete_error = TextField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    has_external_issue_tracker = BooleanField(null=True)
    has_external_wiki = BooleanField(null=True)
    import_error = TextField(null=True)
    import_jid = CharField(null=True)
    import_source = CharField(null=True)
    import_status = CharField(null=True)
    import_type = CharField(null=True)
    import_url = CharField(null=True)
    jobs_cache_index = IntegerField(null=True)
    last_activity_at = DateTimeField(index=True, null=True)
    last_repository_check_at = DateTimeField(null=True)
    last_repository_check_failed = BooleanField(index=True, null=True)
    last_repository_updated_at = DateTimeField(index=True, null=True)
    lfs_enabled = BooleanField(null=True)
    merge_requests_ff_only_enabled = BooleanField()
    merge_requests_rebase_enabled = BooleanField()
    name = CharField(index=True, null=True)
    namespace = IntegerField(column_name='namespace_id', index=True)
    only_allow_merge_if_all_discussions_are_resolved = BooleanField(null=True)
    only_allow_merge_if_pipeline_succeeds = BooleanField()
    path = CharField(index=True, null=True)
    pending_delete = BooleanField(index=True, null=True)
    printing_merge_request_link_enabled = BooleanField()
    public_builds = BooleanField()
    repository_read_only = BooleanField(null=True)
    repository_storage = CharField(index=True)
    request_access_enabled = BooleanField()
    resolve_outdated_diff_discussions = BooleanField(null=True)
    runners_token = CharField(index=True, null=True)
    shared_runners_enabled = BooleanField()
    star_count = IntegerField(index=True)
    storage_version = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField(index=True)

    class Meta:
        table_name = 'projects'

class Badges(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    image_url = CharField()
    link_url = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    type = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'badges'

class Boards(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'boards'

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
        table_name = 'broadcast_messages'
        indexes = (
            (('id', 'starts_at', 'ends_at'), False),
        )

class ChatNames(BaseModel):
    chat = CharField(column_name='chat_id')
    chat_name = CharField(null=True)
    created_at = DateTimeField()
    last_used_at = DateTimeField(null=True)
    service = IntegerField(column_name='service_id')
    team_domain = CharField(null=True)
    team = CharField(column_name='team_id')
    updated_at = DateTimeField()
    user = IntegerField(column_name='user_id')

    class Meta:
        table_name = 'chat_names'
        indexes = (
            (('service', 'team', 'chat'), True),
            (('user', 'service'), True),
        )

class ChatTeams(BaseModel):
    created_at = DateTimeField()
    name = CharField(null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, unique=True)
    team = CharField(column_name='team_id', null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'chat_teams'

class CiBuildTraceSectionNames(BaseModel):
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_build_trace_section_names'
        indexes = (
            (('project', 'name'), True),
        )

class Users(BaseModel):
    admin = BooleanField(index=True)
    avatar = CharField(null=True)
    bio = CharField(null=True)
    can_create_group = BooleanField()
    can_create_team = BooleanField()
    color_scheme = IntegerField(column_name='color_scheme_id')
    confirmation_sent_at = DateTimeField(null=True)
    confirmation_token = CharField(null=True, unique=True)
    confirmed_at = DateTimeField(null=True)
    consumed_timestep = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    created_by = IntegerField(column_name='created_by_id', null=True)
    current_sign_in_at = DateTimeField(null=True)
    current_sign_in_ip = CharField(null=True)
    dashboard = IntegerField(null=True)
    email = CharField(index=True)
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
    theme = IntegerField(column_name='theme_id', null=True)
    twitter = CharField()
    two_factor_grace_period = IntegerField()
    unconfirmed_email = CharField(null=True)
    unlock_token = CharField(null=True)
    updated_at = DateTimeField(null=True)
    username = CharField(index=True, null=True)
    website_url = CharField()

    class Meta:
        table_name = 'users'

class CiPipelineSchedules(BaseModel):
    active = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    cron = CharField(null=True)
    cron_timezone = CharField(null=True)
    description = CharField(null=True)
    next_run_at = DateTimeField(null=True)
    owner = ForeignKeyField(column_name='owner_id', field='id', model=Users, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    ref = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_pipeline_schedules'
        indexes = (
            (('next_run_at', 'active'), False),
        )

class CiPipelines(BaseModel):
    auto_canceled_by = ForeignKeyField(column_name='auto_canceled_by_id', field='id', model='self', null=True)
    before_sha = CharField(null=True)
    committed_at = DateTimeField(null=True)
    config_source = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    duration = IntegerField(null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    pipeline_schedule = ForeignKeyField(column_name='pipeline_schedule_id', field='id', model=CiPipelineSchedules, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    protected = BooleanField(null=True)
    ref = CharField(null=True)
    sha = CharField(null=True)
    source = IntegerField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(index=True, null=True)
    tag = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', index=True, null=True)
    yaml_errors = TextField(null=True)

    class Meta:
        table_name = 'ci_pipelines'
        indexes = (
            (('id', 'ref', 'project', 'status'), False),
            (('sha', 'project'), False),
        )

class CiStages(BaseModel):
    created_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    name = CharField(null=True)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    status = IntegerField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_stages'
        indexes = (
            (('pipeline', 'name'), True),
        )

class CiBuilds(BaseModel):
    allow_failure = BooleanField()
    artifacts_expire_at = DateTimeField(index=True, null=True)
    artifacts_file = TextField(null=True)
    artifacts_metadata = TextField(null=True)
    artifacts_size = BigIntegerField(null=True)
    auto_canceled_by = ForeignKeyField(column_name='auto_canceled_by_id', field='id', model=CiPipelines, null=True)
    commands = TextField(null=True)
    commit = IntegerField(column_name='commit_id', null=True)
    coverage = FloatField(null=True)
    coverage_regex = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    environment = CharField(null=True)
    erased_at = DateTimeField(null=True)
    erased_by = IntegerField(column_name='erased_by_id', null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    lock_version = IntegerField(null=True)
    name = CharField(null=True)
    options = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    protected = BooleanField(index=True, null=True)
    queued_at = DateTimeField(null=True)
    ref = CharField(null=True)
    retried = BooleanField(null=True)
    runner = IntegerField(column_name='runner_id', index=True, null=True)
    stage = CharField(null=True)
    stage_id = ForeignKeyField(column_name='stage_id', field='id', model=CiStages, null=True)
    stage_idx = IntegerField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(index=True, null=True)
    tag = BooleanField(null=True)
    target_url = CharField(null=True)
    token = CharField(null=True, unique=True)
    trace = TextField(null=True)
    trigger_request = IntegerField(column_name='trigger_request_id', null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    user = IntegerField(column_name='user_id', index=True, null=True)
    when = CharField(null=True)
    yaml_variables = TextField(null=True)

    class Meta:
        table_name = 'ci_builds'
        indexes = (
            (('commit', 'created_at', 'stage_idx'), False),
            (('commit', 'name', 'type', 'ref'), False),
            (('commit', 'ref', 'type'), False),
            (('id', 'project'), False),
            (('runner', 'status', 'type'), False),
            (('type', 'status', 'commit'), False),
        )

class CiBuildTraceSections(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    byte_end = BigIntegerField()
    byte_start = BigIntegerField()
    date_end = DateTimeField()
    date_start = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    section_name = ForeignKeyField(column_name='section_name_id', field='id', model=CiBuildTraceSectionNames)

    class Meta:
        table_name = 'ci_build_trace_sections'
        indexes = (
            (('build', 'section_name'), True),
        )

class CiGroupVariables(BaseModel):
    created_at = DateTimeField()
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    key = CharField()
    protected = BooleanField()
    updated_at = DateTimeField()
    value = TextField(null=True)

    class Meta:
        table_name = 'ci_group_variables'
        indexes = (
            (('key', 'group'), True),
        )

class CiJobArtifacts(BaseModel):
    created_at = DateTimeField()
    expire_at = DateTimeField(null=True)
    file = CharField(null=True)
    file_sha256 = BlobField(null=True)
    file_type = IntegerField()
    job = ForeignKeyField(column_name='job_id', field='id', model=CiBuilds)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    size = BigIntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_job_artifacts'
        indexes = (
            (('job', 'expire_at'), False),
            (('job', 'file_type'), True),
        )

class CiPipelineScheduleVariables(BaseModel):
    created_at = DateTimeField(null=True)
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline_schedule = ForeignKeyField(column_name='pipeline_schedule_id', field='id', model=CiPipelineSchedules)
    updated_at = DateTimeField(null=True)
    value = TextField(null=True)

    class Meta:
        table_name = 'ci_pipeline_schedule_variables'
        indexes = (
            (('key', 'pipeline_schedule'), True),
        )

class CiPipelineVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    value = TextField(null=True)

    class Meta:
        table_name = 'ci_pipeline_variables'
        indexes = (
            (('key', 'pipeline'), True),
        )

class CiRunnerProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    runner = IntegerField(column_name='runner_id', index=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_runner_projects'

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
    name = CharField(null=True)
    platform = CharField(null=True)
    revision = CharField(null=True)
    run_untagged = BooleanField()
    token = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    version = CharField(null=True)

    class Meta:
        table_name = 'ci_runners'

class CiTriggers(BaseModel):
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    owner = ForeignKeyField(column_name='owner_id', field='id', model=Users, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    ref = CharField(null=True)
    token = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_triggers'

class CiTriggerRequests(BaseModel):
    commit = IntegerField(column_name='commit_id', index=True, null=True)
    created_at = DateTimeField(null=True)
    trigger = ForeignKeyField(column_name='trigger_id', field='id', model=CiTriggers)
    updated_at = DateTimeField(null=True)
    variables = TextField(null=True)

    class Meta:
        table_name = 'ci_trigger_requests'

class CiVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    environment_scope = CharField()
    key = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    protected = BooleanField()
    value = TextField(null=True)

    class Meta:
        table_name = 'ci_variables'
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
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'clusters'

class ClusterPlatformsKubernetes(BaseModel):
    api_url = TextField(null=True)
    ca_cert = TextField(null=True)
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_password = TextField(null=True)
    encrypted_password_iv = CharField(null=True)
    encrypted_token = TextField(null=True)
    encrypted_token_iv = CharField(null=True)
    namespace = CharField(null=True)
    updated_at = DateTimeField()
    username = CharField(null=True)

    class Meta:
        table_name = 'cluster_platforms_kubernetes'

class ClusterProjects(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'cluster_projects'

class ClusterProvidersGcp(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_access_token = TextField(null=True)
    encrypted_access_token_iv = CharField(null=True)
    endpoint = CharField(null=True)
    gcp_project = CharField(column_name='gcp_project_id')
    machine_type = CharField(null=True)
    num_nodes = IntegerField()
    operation = CharField(column_name='operation_id', null=True)
    status = IntegerField(null=True)
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    zone = CharField()

    class Meta:
        table_name = 'cluster_providers_gcp'

class ClustersApplicationsHelm(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    created_at = DateTimeField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_helm'

class ClustersApplicationsIngress(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    cluster_ip = CharField(null=True)
    created_at = DateTimeField()
    external_ip = CharField(null=True)
    ingress_type = IntegerField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_ingress'

class ClustersApplicationsPrometheus(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    created_at = DateTimeField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_prometheus'

class ClustersApplicationsRunners(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    privileged = BooleanField()
    runner = ForeignKeyField(column_name='runner_id', field='id', model=CiRunners, null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_runners'

class ContainerRepositories(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'container_repositories'
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
        table_name = 'conversational_development_index_metrics'

class DeployKeysProjects(BaseModel):
    can_push = BooleanField()
    created_at = DateTimeField(null=True)
    deploy_key = IntegerField(column_name='deploy_key_id')
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'deploy_keys_projects'

class Deployments(BaseModel):
    created_at = DateTimeField(index=True, null=True)
    deployable = IntegerField(column_name='deployable_id', null=True)
    deployable_type = CharField(null=True)
    environment = IntegerField(column_name='environment_id')
    iid = IntegerField()
    on_stop = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    ref = CharField()
    sha = CharField()
    tag = BooleanField()
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', null=True)

    class Meta:
        table_name = 'deployments'
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
    user = IntegerField(column_name='user_id', index=True)

    class Meta:
        table_name = 'emails'

class Environments(BaseModel):
    created_at = DateTimeField(null=True)
    environment_type = CharField(null=True)
    external_url = CharField(null=True)
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    slug = CharField()
    state = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'environments'
        indexes = (
            (('project', 'name'), True),
            (('project', 'slug'), True),
        )

class Events(BaseModel):
    action = IntegerField(index=True)
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    target = IntegerField(column_name='target_id', null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'events'
        indexes = (
            (('project', 'author'), False),
            (('project', 'id'), False),
            (('target_type', 'target'), False),
        )

class FeatureGates(BaseModel):
    created_at = DateTimeField()
    feature_key = CharField()
    key = CharField()
    updated_at = DateTimeField()
    value = CharField(null=True)

    class Meta:
        table_name = 'feature_gates'
        indexes = (
            (('feature_key', 'key', 'value'), True),
        )

class Features(BaseModel):
    created_at = DateTimeField()
    key = CharField(unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'features'

class ForkNetworks(BaseModel):
    deleted_root_project_name = CharField(null=True)
    root_project = ForeignKeyField(column_name='root_project_id', field='id', model=Projects, null=True, unique=True)

    class Meta:
        table_name = 'fork_networks'

class ForkNetworkMembers(BaseModel):
    fork_network = ForeignKeyField(column_name='fork_network_id', field='id', model=ForkNetworks)
    forked_from_project = ForeignKeyField(column_name='forked_from_project_id', field='id', model=Projects, null=True)
    project = ForeignKeyField(backref='projects_project_set', column_name='project_id', field='id', model=Projects, unique=True)

    class Meta:
        table_name = 'fork_network_members'

class ForkedProjectLinks(BaseModel):
    created_at = DateTimeField(null=True)
    forked_from_project = IntegerField(column_name='forked_from_project_id')
    forked_to_project = ForeignKeyField(column_name='forked_to_project_id', field='id', model=Projects, unique=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'forked_project_links'

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
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    properties = TextField(null=True)
    push_events = BooleanField(null=True)
    tag_push_events = BooleanField(null=True)
    template = BooleanField(index=True, null=True)
    title = CharField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    wiki_page_events = BooleanField(null=True)

    class Meta:
        table_name = 'services'

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
    gcp_operation = CharField(column_name='gcp_operation_id', null=True)
    gcp_project = CharField(column_name='gcp_project_id')
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    project_namespace = CharField(null=True)
    service = ForeignKeyField(column_name='service_id', field='id', model=Services, null=True)
    status = IntegerField(null=True)
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)
    username = CharField(null=True)

    class Meta:
        table_name = 'gcp_clusters'

class GpgKeys(BaseModel):
    created_at = DateTimeField()
    fingerprint = BlobField(null=True, unique=True)
    key = TextField(null=True)
    primary_keyid = BlobField(null=True, unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'gpg_keys'

class GpgKeySubkeys(BaseModel):
    fingerprint = BlobField(null=True, unique=True)
    gpg_key = ForeignKeyField(column_name='gpg_key_id', field='id', model=GpgKeys)
    keyid = BlobField(null=True, unique=True)

    class Meta:
        table_name = 'gpg_key_subkeys'

class GpgSignatures(BaseModel):
    commit_sha = BlobField(null=True, unique=True)
    created_at = DateTimeField()
    gpg_key = ForeignKeyField(column_name='gpg_key_id', field='id', model=GpgKeys, null=True)
    gpg_key_primary_keyid = BlobField(index=True, null=True)
    gpg_key_subkey = ForeignKeyField(column_name='gpg_key_subkey_id', field='id', model=GpgKeySubkeys, null=True)
    gpg_key_user_email = TextField(null=True)
    gpg_key_user_name = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()
    verification_status = IntegerField()

    class Meta:
        table_name = 'gpg_signatures'

class GroupCustomAttributes(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    key = CharField()
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        table_name = 'group_custom_attributes'
        indexes = (
            (('group', 'key'), True),
            (('key', 'value'), False),
        )

class Identities(BaseModel):
    created_at = DateTimeField(null=True)
    extern_uid = CharField(null=True)
    provider = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', index=True, null=True)

    class Meta:
        table_name = 'identities'

class Milestones(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    due_date = DateField(index=True, null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    iid = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    start_date = DateField(null=True)
    state = CharField(null=True)
    title = CharField(index=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'milestones'
        indexes = (
            (('project', 'iid'), True),
        )

class Issues(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    cached_markdown_version = IntegerField(null=True)
    closed_at = DateTimeField(null=True)
    confidential = BooleanField(index=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    discussion_locked = BooleanField(null=True)
    due_date = DateField(null=True)
    iid = IntegerField(null=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by = IntegerField(column_name='last_edited_by_id', null=True)
    lock_version = IntegerField(null=True)
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones, null=True)
    moved_to = ForeignKeyField(column_name='moved_to_id', field='id', model='self', null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    relative_position = IntegerField(index=True, null=True)
    state = CharField(index=True, null=True)
    time_estimate = IntegerField(null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    updated_by = ForeignKeyField(backref='users_updated_by_set', column_name='updated_by_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'issues'
        indexes = (
            (('project', 'id', 'created_at', 'state'), False),
            (('project', 'id', 'state', 'updated_at'), False),
            (('project', 'iid'), True),
            (('state', 'due_date', 'project', 'id'), False),
        )

class IssueAssignees(BaseModel):
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'issue_assignees'
        indexes = (
            (('user', 'issue'), True),
        )
        primary_key = False

class IssueMetrics(BaseModel):
    created_at = DateTimeField()
    first_added_to_board_at = DateTimeField(null=True)
    first_associated_with_milestone_at = DateTimeField(null=True)
    first_mentioned_in_commit_at = DateTimeField(null=True)
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issue_metrics'

class Keys(BaseModel):
    created_at = DateTimeField(null=True)
    fingerprint = CharField(null=True, unique=True)
    key = TextField(null=True)
    last_used_at = DateTimeField(null=True)
    public = BooleanField()
    title = CharField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', index=True, null=True)

    class Meta:
        table_name = 'keys'

class LabelLinks(BaseModel):
    created_at = DateTimeField(null=True)
    label = IntegerField(column_name='label_id', index=True, null=True)
    target = IntegerField(column_name='target_id', null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'label_links'
        indexes = (
            (('target', 'target_type'), False),
        )

class Labels(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    description_html = TextField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    template = BooleanField(index=True, null=True)
    title = CharField(index=True, null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'labels'
        indexes = (
            (('title', 'group', 'project'), True),
            (('type', 'project'), False),
        )

class LabelPriorities(BaseModel):
    created_at = DateTimeField()
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels)
    priority = IntegerField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'label_priorities'
        indexes = (
            (('project', 'label'), True),
        )

class LfsFileLocks(BaseModel):
    created_at = DateTimeField()
    path = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'lfs_file_locks'
        indexes = (
            (('project', 'path'), True),
        )

class LfsObjects(BaseModel):
    created_at = DateTimeField(null=True)
    file = CharField(null=True)
    oid = CharField(unique=True)
    size = BigIntegerField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'lfs_objects'

class LfsObjectsProjects(BaseModel):
    created_at = DateTimeField(null=True)
    lfs_object = IntegerField(column_name='lfs_object_id')
    project = IntegerField(column_name='project_id', index=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'lfs_objects_projects'

class Lists(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)
    created_at = DateTimeField()
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels, null=True)
    list_type = IntegerField()
    position = IntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'lists'
        indexes = (
            (('board', 'label'), True),
        )

class Members(BaseModel):
    access_level = IntegerField(index=True)
    created_at = DateTimeField(null=True)
    created_by = IntegerField(column_name='created_by_id', null=True)
    expires_at = DateField(null=True)
    invite_accepted_at = DateTimeField(null=True)
    invite_email = CharField(null=True)
    invite_token = CharField(null=True, unique=True)
    notification_level = IntegerField()
    requested_at = DateTimeField(index=True, null=True)
    source = IntegerField(column_name='source_id')
    source_type = CharField()
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'members'
        indexes = (
            (('source_type', 'source'), False),
        )

class Notes(BaseModel):
    attachment = CharField(null=True)
    author = IntegerField(column_name='author_id', index=True, null=True)
    cached_markdown_version = IntegerField(null=True)
    change_position = TextField(null=True)
    commit = CharField(column_name='commit_id', index=True, null=True)
    created_at = DateTimeField(index=True, null=True)
    discussion = CharField(column_name='discussion_id', index=True, null=True)
    line_code = CharField(index=True, null=True)
    note = TextField(index=True, null=True)
    note_html = TextField(null=True)
    noteable = IntegerField(column_name='noteable_id', null=True)
    noteable_type = CharField(index=True, null=True)
    original_position = TextField(null=True)
    position = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    resolved_at = DateTimeField(null=True)
    resolved_by = IntegerField(column_name='resolved_by_id', null=True)
    resolved_by_push = BooleanField(null=True)
    st_diff = TextField(null=True)
    system = BooleanField()
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    updated_by = IntegerField(column_name='updated_by_id', null=True)

    class Meta:
        table_name = 'notes'
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
    reassign_issue = BooleanField(null=True)
    reassign_merge_request = BooleanField(null=True)
    reopen_issue = BooleanField(null=True)
    reopen_merge_request = BooleanField(null=True)
    source = IntegerField(column_name='source_id', null=True)
    source_type = CharField(null=True)
    success_pipeline = BooleanField(null=True)
    updated_at = DateTimeField()
    user = IntegerField(column_name='user_id', index=True)

    class Meta:
        table_name = 'notification_settings'
        indexes = (
            (('source', 'source_type'), False),
            (('source', 'source_type', 'user'), True),
        )

class OauthAccessGrants(BaseModel):
    application = IntegerField(column_name='application_id')
    created_at = DateTimeField()
    expires_in = IntegerField()
    redirect_uri = TextField()
    resource_owner = IntegerField(column_name='resource_owner_id')
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        table_name = 'oauth_access_grants'

class OauthAccessTokens(BaseModel):
    application = IntegerField(column_name='application_id', null=True)
    created_at = DateTimeField()
    expires_in = IntegerField(null=True)
    refresh_token = CharField(null=True, unique=True)
    resource_owner = IntegerField(column_name='resource_owner_id', index=True, null=True)
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        table_name = 'oauth_access_tokens'

class OauthApplications(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField()
    owner = IntegerField(column_name='owner_id', null=True)
    owner_type = CharField(null=True)
    redirect_uri = TextField()
    scopes = CharField()
    secret = CharField()
    trusted = BooleanField()
    uid = CharField(unique=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'oauth_applications'
        indexes = (
            (('owner', 'owner_type'), False),
        )

class OauthOpenidRequests(BaseModel):
    access_grant = ForeignKeyField(column_name='access_grant_id', field='id', model=OauthAccessGrants)
    nonce = CharField()

    class Meta:
        table_name = 'oauth_openid_requests'

class PagesDomains(BaseModel):
    certificate = TextField(null=True)
    domain = CharField(null=True, unique=True)
    enabled_until = DateTimeField(null=True)
    encrypted_key = TextField(null=True)
    encrypted_key_iv = CharField(null=True)
    encrypted_key_salt = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    verification_code = CharField()
    verified_at = DateTimeField(index=True, null=True)

    class Meta:
        table_name = 'pages_domains'
        indexes = (
            (('project', 'enabled_until'), False),
            (('verified_at', 'enabled_until'), False),
        )

class PersonalAccessTokens(BaseModel):
    created_at = DateTimeField()
    expires_at = DateField(null=True)
    impersonation = BooleanField()
    name = CharField()
    revoked = BooleanField(null=True)
    scopes = CharField()
    token = CharField(unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'personal_access_tokens'

class ProjectAuthorizations(BaseModel):
    access_level = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'project_authorizations'
        indexes = (
            (('user', 'project', 'access_level'), True),
        )
        primary_key = False

class ProjectAutoDevops(BaseModel):
    created_at = DateTimeField()
    domain = CharField(null=True)
    enabled = BooleanField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_auto_devops'

class ProjectCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        table_name = 'project_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('project', 'key'), True),
        )

class ProjectFeatures(BaseModel):
    builds_access_level = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    issues_access_level = IntegerField(null=True)
    merge_requests_access_level = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    repository_access_level = IntegerField()
    snippets_access_level = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    wiki_access_level = IntegerField(null=True)

    class Meta:
        table_name = 'project_features'

class ProjectGroupLinks(BaseModel):
    created_at = DateTimeField(null=True)
    expires_at = DateField(null=True)
    group_access = IntegerField()
    group = IntegerField(column_name='group_id', index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'project_group_links'

class ProjectImportData(BaseModel):
    data = TextField(null=True)
    encrypted_credentials = TextField(null=True)
    encrypted_credentials_iv = CharField(null=True)
    encrypted_credentials_salt = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)

    class Meta:
        table_name = 'project_import_data'

class ProjectStatistics(BaseModel):
    build_artifacts_size = BigIntegerField()
    commit_count = BigIntegerField()
    lfs_objects_size = BigIntegerField()
    namespace = IntegerField(column_name='namespace_id', index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    repository_size = BigIntegerField()
    storage_size = BigIntegerField()

    class Meta:
        table_name = 'project_statistics'

class ProtectedBranches(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'protected_branches'

class ProtectedBranchMergeAccessLevels(BaseModel):
    access_level = IntegerField()
    created_at = DateTimeField()
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'protected_branch_merge_access_levels'

class ProtectedBranchPushAccessLevels(BaseModel):
    access_level = IntegerField()
    created_at = DateTimeField()
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'protected_branch_push_access_levels'

class ProtectedTags(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'protected_tags'

class ProtectedTagCreateAccessLevels(BaseModel):
    access_level = IntegerField(null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_tag = ForeignKeyField(column_name='protected_tag_id', field='id', model=ProtectedTags)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_tag_create_access_levels'

class PushEventPayloads(BaseModel):
    action = IntegerField()
    commit_count = BigIntegerField()
    commit_from = BlobField(null=True)
    commit_title = CharField(null=True)
    commit_to = BlobField(null=True)
    event = ForeignKeyField(column_name='event_id', field='id', model=Events, unique=True)
    ref = TextField(null=True)
    ref_type = IntegerField()

    class Meta:
        table_name = 'push_event_payloads'
        primary_key = False

class RedirectRoutes(BaseModel):
    created_at = DateTimeField()
    path = CharField(unique=True)
    permanent = BooleanField(null=True)
    source = IntegerField(column_name='source_id')
    source_type = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'redirect_routes'
        indexes = (
            (('source', 'source_type'), False),
        )

class Releases(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(null=True)
    description_html = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    tag = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'releases'
        indexes = (
            (('tag', 'project'), False),
        )

class Routes(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField(null=True)
    path = CharField(index=True)
    source = IntegerField(column_name='source_id')
    source_type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'routes'
        indexes = (
            (('source', 'source_type'), True),
        )

class SchemaMigrations(BaseModel):
    version = CharField(unique=True)

    class Meta:
        table_name = 'schema_migrations'
        primary_key = False

class SentNotifications(BaseModel):
    commit = CharField(column_name='commit_id', null=True)
    in_reply_to_discussion = CharField(column_name='in_reply_to_discussion_id', null=True)
    line_code = CharField(null=True)
    note_type = CharField(null=True)
    noteable = IntegerField(column_name='noteable_id', null=True)
    noteable_type = CharField(null=True)
    position = TextField(null=True)
    project = IntegerField(column_name='project_id', null=True)
    recipient = IntegerField(column_name='recipient_id', null=True)
    reply_key = CharField(unique=True)

    class Meta:
        table_name = 'sent_notifications'

class Snippets(BaseModel):
    author = IntegerField(column_name='author_id', index=True)
    cached_markdown_version = IntegerField(null=True)
    content = TextField(null=True)
    content_html = TextField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(null=True)
    description_html = TextField(null=True)
    file_name = CharField(index=True, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    visibility_level = IntegerField(index=True)

    class Meta:
        table_name = 'snippets'

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
    user = IntegerField(column_name='user_id', null=True)
    via_api = BooleanField(null=True)

    class Meta:
        table_name = 'spam_logs'

class Subscriptions(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    subscribable = IntegerField(column_name='subscribable_id', null=True)
    subscribable_type = CharField(null=True)
    subscribed = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id', null=True)

    class Meta:
        table_name = 'subscriptions'
        indexes = (
            (('user', 'subscribable', 'subscribable_type', 'project'), True),
        )

class SystemNoteMetadata(BaseModel):
    action = CharField(null=True)
    commit_count = IntegerField(null=True)
    created_at = DateTimeField()
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'system_note_metadata'

class Taggings(BaseModel):
    context = CharField(null=True)
    created_at = DateTimeField(null=True)
    tag = IntegerField(column_name='tag_id', index=True, null=True)
    taggable = IntegerField(column_name='taggable_id', null=True)
    taggable_type = CharField(null=True)
    tagger = IntegerField(column_name='tagger_id', null=True)
    tagger_type = CharField(null=True)

    class Meta:
        table_name = 'taggings'
        indexes = (
            (('taggable', 'taggable_type', 'context'), False),
            (('taggable_type', 'taggable'), False),
            (('tagger', 'context', 'tagger_type', 'tag', 'taggable', 'taggable_type'), True),
        )

class Tags(BaseModel):
    name = CharField(null=True, unique=True)
    taggings_count = IntegerField(null=True)

    class Meta:
        table_name = 'tags'

class Todos(BaseModel):
    action = IntegerField()
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    commit = CharField(column_name='commit_id', index=True, null=True)
    created_at = DateTimeField(null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    state = CharField()
    target = IntegerField(column_name='target_id', null=True)
    target_type = CharField()
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(backref='users_user_set', column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'todos'
        indexes = (
            (('id', 'user'), False),
            (('target_type', 'target'), False),
            (('user', 'id'), False),
        )

class TrendingProjects(BaseModel):
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)

    class Meta:
        table_name = 'trending_projects'

class U2FRegistrations(BaseModel):
    certificate = TextField(null=True)
    counter = IntegerField(null=True)
    created_at = DateTimeField()
    key_handle = CharField(index=True, null=True)
    name = CharField(null=True)
    public_key = CharField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'u2f_registrations'

class UntrackedFilesForUploads(BaseModel):
    path = CharField(unique=True)

    class Meta:
        table_name = 'untracked_files_for_uploads'

class Uploads(BaseModel):
    checksum = CharField(index=True, null=True)
    created_at = DateTimeField()
    model = IntegerField(column_name='model_id', null=True)
    model_type = CharField(null=True)
    mount_point = CharField(null=True)
    path = CharField()
    secret = CharField(null=True)
    size = BigIntegerField()
    uploader = CharField()

    class Meta:
        table_name = 'uploads'
        indexes = (
            (('model', 'model_type'), False),
            (('path', 'uploader'), False),
        )

class UserAgentDetails(BaseModel):
    created_at = DateTimeField()
    ip_address = CharField()
    subject = IntegerField(column_name='subject_id')
    subject_type = CharField()
    submitted = BooleanField()
    updated_at = DateTimeField()
    user_agent = CharField()

    class Meta:
        table_name = 'user_agent_details'
        indexes = (
            (('subject', 'subject_type'), False),
        )

class UserCallouts(BaseModel):
    feature_name = IntegerField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'user_callouts'
        indexes = (
            (('feature_name', 'user'), True),
        )

class UserCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)
    value = CharField()

    class Meta:
        table_name = 'user_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('user', 'key'), True),
        )

class UserInteractedProjects(BaseModel):
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'user_interacted_projects'
        indexes = (
            (('user', 'project'), True),
        )
        primary_key = False

class UserSyncedAttributesMetadata(BaseModel):
    email_synced = BooleanField(null=True)
    location_synced = BooleanField(null=True)
    name_synced = BooleanField(null=True)
    provider = CharField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, unique=True)

    class Meta:
        table_name = 'user_synced_attributes_metadata'

class UsersStarProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)
    user = IntegerField(column_name='user_id')

    class Meta:
        table_name = 'users_star_projects'
        indexes = (
            (('project', 'user'), True),
        )

class WebHooks(BaseModel):
    confidential_issues_events = BooleanField()
    confidential_note_events = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    enable_ssl_verification = BooleanField(null=True)
    issues_events = BooleanField()
    job_events = BooleanField()
    merge_requests_events = BooleanField()
    note_events = BooleanField()
    pipeline_events = BooleanField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    push_events = BooleanField()
    repository_update_events = BooleanField()
    service = IntegerField(column_name='service_id', null=True)
    tag_push_events = BooleanField(null=True)
    token = CharField(null=True)
    type = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    url = CharField(null=True)
    wiki_page_events = BooleanField()

    class Meta:
        table_name = 'web_hooks'

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
    web_hook = ForeignKeyField(column_name='web_hook_id', field='id', model=WebHooks)

    class Meta:
        table_name = 'web_hook_logs'

