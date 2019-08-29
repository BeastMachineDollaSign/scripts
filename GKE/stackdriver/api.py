
import argparse
import json
import os
import pickle
import shutil
import datetime
import tempfile

from google.cloud import monitoring_v3
import google.protobuf.json_format
import tabulate

def __sanitize_filename(filename):
    return "".join([c for c in filename.lower() if c.isalpha() or c.isdigit()])

# [START monitoring_alert_list_policies]
def list_alert_policies(project_name):
    client = monitoring_v3.AlertPolicyServiceClient()
    policies = client.list_alert_policies(project_name)
    print(tabulate.tabulate(
        [(policy.name, policy.display_name) for policy in policies],
        ('name', 'display_name')))
# [END monitoring_alert_list_policies]


# [START monitoring_alert_list_channels]
def list_notification_channels(project_name):
    client = monitoring_v3.NotificationChannelServiceClient()
    channels = client.list_notification_channels(project_name)
    print(tabulate.tabulate(
        [(channel.name, channel.display_name) for channel in channels],
        ('name', 'display_name')))
# [END monitoring_alert_list_channels]


# [START monitoring_alert_enable_policies]
def enable_alert_policies(project_name, enable, filter_=None):
    """Enable or disable alert policies in a project.
    Arguments:
        project_name (str)
        enable (bool): Enable or disable the policies.
        filter_ (str, optional): Only enable/disable alert policies that match
            this filter_.  See
            https://cloud.google.com/monitoring/api/v3/sorting-and-filtering
    """

    client = monitoring_v3.AlertPolicyServiceClient()
    policies = client.list_alert_policies(project_name, filter_=filter_)

    for policy in policies:
        if bool(enable) == policy.enabled.value:
            print('Policy', policy.name, 'is already',
                  'enabled' if policy.enabled.value else 'disabled')
        else:
            policy.enabled.value = bool(enable)
            mask = monitoring_v3.types.field_mask_pb2.FieldMask()
            mask.paths.append('enabled')
            client.update_alert_policy(policy, mask)
            print('Enabled' if enable else 'Disabled', policy.name)
# [END monitoring_alert_enable_policies]


# [START monitoring_alert_replace_channels]
def replace_notification_channels(project_name, alert_policy_id, channel_ids):
    _, project_id = project_name.split('/')
    alert_client = monitoring_v3.AlertPolicyServiceClient()
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    policy = monitoring_v3.types.alert_pb2.AlertPolicy()
    policy.name = alert_client.alert_policy_path(project_id, alert_policy_id)

    for channel_id in channel_ids:
        policy.notification_channels.append(
            channel_client.notification_channel_path(project_id, channel_id))

    mask = monitoring_v3.types.field_mask_pb2.FieldMask()
    mask.paths.append('notification_channels')
    updated_policy = alert_client.update_alert_policy(policy, mask)
    print('Updated', updated_policy.name)
# [END monitoring_alert_replace_channels]


# [START monitoring_alert_delete_channel]
def delete_notification_channels(project_name, channel_ids, force=None):
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    for channel_id in channel_ids:
        channel_name = '{}/notificationChannels/{}'.format(
            project_name, channel_id)
        try:
            channel_client.delete_notification_channel(
                channel_name, force=force)
            print('Channel {} deleted'.format(channel_name))
        except ValueError:
            print('The parameters are invalid')
        except Exception as e:
            print('API call failed: {}'.format(e))
# [END monitoring_alert_delete_channel]


# [START monitoring_alert_backup_policies]
def backup(project_name, backup_filename):
    alert_client = monitoring_v3.AlertPolicyServiceClient()
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    record = {'project_name': project_name,
              'policies': list(alert_client.list_alert_policies(project_name)),
              'channels': list(channel_client.list_notification_channels(
                  project_name))}
    json.dump(record, open(backup_filename, 'wt'), cls=ProtoEncoder, indent=2)
    print('Backed up alert policies and notification channels to {}.'.format(
        backup_filename)
    )


class ProtoEncoder(json.JSONEncoder):
    """Uses google.protobuf.json_format to encode protobufs as json."""
    def default(self, obj):
        if type(obj) in (monitoring_v3.types.alert_pb2.AlertPolicy,
                         monitoring_v3.types.notification_pb2.
                         NotificationChannel):
            text = google.protobuf.json_format.MessageToJson(obj)
            return json.loads(text)
        return super(ProtoEncoder, self).default(obj)
# [END monitoring_alert_backup_policies]


# [START monitoring_alert_restore_policies]
# [START monitoring_alert_create_policy]
# [START monitoring_alert_create_channel]
# [START monitoring_alert_update_channel]
# [START monitoring_alert_enable_channel]
def restore(project_name, backup_filename):
    print('Loading alert policies and notification channels from {}.'.format(
        backup_filename)
    )
    record = json.load(open(backup_filename, 'rt'))
    is_same_project = project_name == record['project_name']
    # Convert dicts to AlertPolicies.
    policies_json = [json.dumps(policy) for policy in record['policies']]
    policies = [google.protobuf.json_format.Parse(
        policy_json, monitoring_v3.types.alert_pb2.AlertPolicy())
        for policy_json in policies_json]
    # Convert dicts to NotificationChannels
    channels_json = [json.dumps(channel) for channel in record['channels']]
    channels = [google.protobuf.json_format.Parse(
        channel_json, monitoring_v3.types.notification_pb2.
        NotificationChannel()) for channel_json in channels_json]

    # Restore the channels.
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    channel_name_map = {}

    for channel in channels:
        updated = False
        print('Updating channel', channel.display_name)
        # This field is immutable and it is illegal to specify a
        # non-default value (UNVERIFIED or VERIFIED) in the
        # Create() or Update() operations.
        channel.verification_status = monitoring_v3.enums.NotificationChannel.\
            VerificationStatus.VERIFICATION_STATUS_UNSPECIFIED

        if is_same_project:
            try:
                channel_client.update_notification_channel(channel)
                updated = True
            except google.api_core.exceptions.NotFound:
                pass  # The channel was deleted.  Create it below.

        if not updated:
            # The channel no longer exists.  Recreate it.
            old_name = channel.name
            channel.ClearField("name")
            new_channel = channel_client.create_notification_channel(
                project_name, channel)
            channel_name_map[old_name] = new_channel.name

    # Restore the alerts
    alert_client = monitoring_v3.AlertPolicyServiceClient()

    for policy in policies:
        print('Updating policy', policy.display_name)
        # These two fields cannot be set directly, so clear them.
        policy.ClearField('creation_record')
        policy.ClearField('mutation_record')

        # Update old channel names with new channel names.
        for i, channel in enumerate(policy.notification_channels):
            new_channel = channel_name_map.get(channel)
            if new_channel:
                policy.notification_channels[i] = new_channel

        updated = False

        if is_same_project:
            try:
                alert_client.update_alert_policy(policy)
                updated = True
            except google.api_core.exceptions.NotFound:
                pass  # The policy was deleted.  Create it below.
            except google.api_core.exceptions.InvalidArgument:
                # Annoying that API throws InvalidArgument when the policy
                # does not exist.  Seems like it should throw NotFound.
                pass  # The policy was deleted.  Create it below.

        if not updated:
            # The policy no longer exists.  Recreate it.
            old_name = policy.name
            policy.ClearField("name")
            for condition in policy.conditions:
                condition.ClearField("name")
            policy = alert_client.create_alert_policy(project_name, policy)
        print('Updated', policy.name)
# [END monitoring_alert_enable_channel]
# [END monitoring_alert_restore_policies]
# [END monitoring_alert_create_policy]
# [END monitoring_alert_create_channel]
# [END monitoring_alert_update_channel]


class MissingProjectIdError(Exception):
    pass


def project_id():
    """Retreieves the project id from the environment variable.
    Raises:
        MissingProjectIdError -- When not set.
    Returns:
        str -- the project name
    """
    project_id = os.environ['GCLOUD_PROJECT']

    if not project_id:
        raise MissingProjectIdError(
            'Set the environment variable ' +
            'GCLOUD_PROJECT to your Google Cloud Project Id.')
    return project_id


def project_name():
    return 'projects/' + project_id()


def backup_folder():
    return os.environ["STACK_DRIVER_BACKUP"]


def structured_backup(folder=backup_folder(), project_name=project_name(),permissions=0o755):
    folder = os.path.join(folder, datetime.datetime.now().strftime("%Y%m%d%H%M"))
    alert_client = monitoring_v3.AlertPolicyServiceClient()
    channel_client = monitoring_v3.NotificationChannelServiceClient()
    
    if os.path.exists(folder):
        raise FileExistsError

    os.mkdir(folder)
    os.mkdir(os.path.join(folder, "policies"), permissions)
    os.mkdir(os.path.join(folder, "channels"), permissions)

    for policy in alert_client.list_alert_policies(project_name):
        json.dump(policy, open(os.path.join(folder, "policies", __sanitize_filename(
            policy.display_name)), 'wt'), cls=ProtoEncoder, indent=2)
    for channel in channel_client.list_notification_channels(project_name):
        json.dump(channel, open(os.path.join(folder, "channels", __sanitize_filename(
            channel.display_name)), 'wt'), cls=ProtoEncoder, indent=2)
    print('Backed up alert policies and notification channels to {}.'.format(
        folder)
    )

def structured_restore(folder=backup_folder(), project_name=project_name()):
    record = {'project_name': project_name}
    policies = []
    channels = []
    tmp = tempfile.NamedTemporaryFile()
    policies_folder = os.path.join(folder, "policies")
    channels_folder = os.path.join(folder, "channels")
    for policy in os.listdir(policies_folder):
        with open(os.path.join(policies_folder, policy)) as infile:
            policies.append(json.loads(infile.read()))
    for channel in os.listdir(channels_folder):
        with open(os.path.join(channels_folder, channel)) as infile:
            channels.append(infile.read())
    record["policies"] = policies
    record["channels"] = channels
    with open(tmp.name, 'w') as f:
        json.dump(record, f, cls=ProtoEncoder, indent=2)
    restore(project_name, tmp.name)
