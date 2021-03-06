import datetime
import os
import subprocess
import shlex

import paramiko

from tcbuilder.errors import OperationFailureError, TorizonCoreBuilderError
from tcbuilder.backend.ostree import OSTREE_WHITEOUT_PREFIX, OSTREE_OPAQUE_WHITEOUT_NAME
from tcbuilder.backend.common import resolve_remote_host

IGNORE_FILES = [
    'group-',
    'shadow-',
    'gshadow-',
    'hostname',
    'machine-id',
    'ipk-postinsts',
    'fw_env.conf',
    'docker/key.json',
    '.updated',
    '.pwd.lock',
    'ssh/ssh_host_rsa_key',
    'ssh/ssh_host_rsa_key.pub',
    'ssh/ssh_host_ecdsa_key',
    'ssh/ssh_host_ecdsa_key.pub',
    'ssh/ssh_host_ed25519_key',
    'ssh/ssh_host_ed25519_key.pub',
    'systemd/system/sysinit.target.wants/run-postinsts.service',
    'ostree/remotes.d/toradex-nightly.conf',
]
TAR_NAME = 'isolated_changes.tar'

NO_CHANGES = 0
CHANGES_CAPTURED = 1


def run_command_with_sudo(client, command, password):
    stdin, stdout, _stderr = client.exec_command(command=command, get_pty=True)
    stdin.write(password + '\n')
    stdin.flush()
    status = stdout.channel.recv_exit_status()  # wait for exec_command to finish

    return status, stdin, stdout


def run_command_without_sudo(client, command):
    stdin, stdout, _stderr = client.exec_command(command)
    status = stdout.channel.recv_exit_status()  # wait for exec_command to finish

    return status, stdin, stdout


def ignore_changes_deletion(change):
    # NOTE: this offset must match the output of `ostree admin config`:
    fname = change[5:]
    if not fname or fname in IGNORE_FILES:
        return False  # ignore file

    return True


def remove_tmp_dir(client, tmp_dir_name):
    run_command_without_sudo(client, 'rm -rf ' + tmp_dir_name)


def check_path(path):
    return '/' if path.rsplit('/', 1)[0] == path else '/{}/'.format(
        path.rsplit('/', 1)[0])


def whiteouts(client, sftp_channel, tmp_dir_name, deleted_f_d):
    # check if deleted file/dir was in subdirectory of /etc --> '/' for file/dir at /etc
    path = check_path(deleted_f_d)
    if path != '/':  # file/dir was in subdirectory of /etc
        # check if any file exists other than file/dir deleted in same subdirectory of /etc
        d_list = sftp_channel.listdir('/etc' + path)
        if not d_list:  # entire content(s) deleted
            deleted_file_dir_to_tar = 'etc' + path + OSTREE_OPAQUE_WHITEOUT_NAME
        else:
            deleted_file_dir_to_tar = 'etc' + path + OSTREE_WHITEOUT_PREFIX \
                                        + deleted_f_d.rsplit('/', 1)[1]
    else:
        deleted_file_dir_to_tar = 'etc' + path + OSTREE_WHITEOUT_PREFIX \
                                    + deleted_f_d

    # create deleted files/dir in torizonbuilder tmp directory with whiteout format
    create_deleted_info_cmd = 'mkdir -p {0}/{1} && touch {0}/{2}'.format(
        tmp_dir_name, deleted_file_dir_to_tar.rsplit('/', 1)[0],
        shlex.quote(deleted_file_dir_to_tar))
    status, _stdin, stdout = run_command_without_sudo(client, create_deleted_info_cmd)
    if status > 0:
        raise OperationFailureError(
            f'Could not create dir in {tmp_dir_name}',
            stdout.read().decode('utf-8').strip())


def get_tcattr_file_content(files_dir_to_tar, ssh_client, sftp_client,
                            remote_password, tmp_dir_name):
    """
    Get the content (permission/ownership) for the "/etc/.tcattr"
    metadata file of all files that will be isolated and will be
    used later by the "union" command.
    """

    facl_command = "sudo getfacl -n {0} 2>/dev/null".format(files_dir_to_tar)
    status, _stdin, stdout = run_command_with_sudo(ssh_client, facl_command,
                                                   remote_password)
    if status > 0:
        remove_tmp_dir(ssh_client, tmp_dir_name)
        sftp_client.close()
        ssh_client.close()
        facl_command_error = 'Unable to save permissions/ownership at target'
        raise OperationFailureError(facl_command_error,
                                    stdout.read().decode('utf-8').strip())

    tcattr = stdout.read().decode("utf-8").strip().split("\r\n")
    # remove upto password keyword
    indx = tcattr.index("Password: ")
    tcattr = tcattr[(indx + 1):]
    tcattr = "\n".join(tcattr) + "\n"
    return tcattr


def create_tcattr_file(diff_dir, tcattr):
    """
        Create the {diff_dir}/usr/etc/.tcattr file using the content of
        tcattr buffer so it can be used later by the "union" command to
        set file and/or directory permissions and/or ownership.
    """
    with open(f"{diff_dir}/usr/etc/.tcattr", "w") as fd_tcattr:
        fd_tcattr.write(tcattr.replace('# file: etc/', '# file: '))


def list_to_string_with_quote(args_list):
    """
        Insert quotes where needed so shell can read names with special characters.
        Also, transforms the list into a string
    """
    return r' '.join([shlex.quote(file) for file in args_list])


# pylint: disable=too-many-locals
def isolate_user_changes(diff_dir, r_name_ip, r_username, r_password, r_port, r_mdns):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    resolved_remote_host = resolve_remote_host(r_name_ip, r_mdns)
    client.connect(hostname=resolved_remote_host,
                   username=r_username,
                   password=r_password,
                   port=r_port)
    # get config diff
    status, _stdin, stdout = run_command_with_sudo(
        client, 'sudo ostree admin config-diff', r_password)
    if status > 0:
        client.close()
        raise OperationFailureError('Unable to get user changes',
                                    stdout.read().decode('utf-8').strip())

    output = stdout.read().decode("utf-8").split("\r\n")
    # remove upto password keyword
    indx = output.index("Password: ")
    output = output[(indx + 1):]

    # filter out files
    changed_itr = filter(ignore_changes_deletion, output)
    changes = list(changed_itr)
    if not changes:
        return NO_CHANGES

    # Buffer to store the content for the ".tcattr" file
    tcattr = None

    sftp = client.open_sftp()
    if sftp is not None:
        # perform all operations in /tmp
        tmp_dir_name = '/tmp/torizon-builder-' + str(datetime.datetime.now().date()) + '_' + str(
            datetime.datetime.now().time()).replace(':', '-')
        sftp.mkdir(tmp_dir_name)

        files_dir_to_tar = ''
        files_list = []
        f_delete_exists = False
        # append /etc because ostree config provides file/dir names relative to /etc
        for item in changes:
            f_name = item[5:]   # Sync with ignore_changes_deletion
            if item[0] != 'D':
                files_list.append('/etc/' + f_name)
            else:
                f_delete_exists = True
                whiteouts(client, sftp, tmp_dir_name, f_name)

        files_dir_to_tar = list_to_string_with_quote(files_list)
        if f_delete_exists:
            tar_command = "sudo tar --exclude={0} --xattrs --acls -cf {1}/{0} -C {1} . {2}". \
                format(TAR_NAME, tmp_dir_name, files_dir_to_tar)
        else:
            # don't include current directory i.e. '.':
            # whiteout files does not exist in /tmp/torizon-builder/
            tar_command = "sudo tar --xattrs --acls -cf {1}/{0} {2}".format(
                TAR_NAME, tmp_dir_name, files_dir_to_tar)
        # make tar
        status, _stdin, stdout = run_command_with_sudo(client, tar_command, r_password)
        if status > 0:
            remove_tmp_dir(client, tmp_dir_name)
            sftp.close()
            client.close()
            raise OperationFailureError('Unable to bundle up changes at target',
                                        stdout.read().decode('utf-8').strip())

        # get the tar
        sftp.get(tmp_dir_name + '/' + TAR_NAME, diff_dir + '/' + TAR_NAME, None)
        remove_tmp_dir(client, tmp_dir_name)
        sftp.close()

        tcattr = get_tcattr_file_content(files_dir_to_tar, client, sftp,
                                         r_password, tmp_dir_name)
    else:
        client.close()
        raise TorizonCoreBuilderError('Unable to create SSH connection for transferring of files')

    client.close()

    # Extract tar to diff_dir/usr/ so that at time of union
    # they can be committed to /usr/etc of unpacked image as it is
    os.mkdir(os.path.join(diff_dir, "usr"))
    extract_tar_cmd = [
        "tar", "--acls", "--xattrs", "--overwrite", "--preserve-permissions", "-xf",
        os.path.join(diff_dir, TAR_NAME), "-C", os.path.join(diff_dir, "usr", "")
    ]
    subprocess.check_output(extract_tar_cmd, stderr=subprocess.STDOUT)

    create_tcattr_file(diff_dir, tcattr)

    os.remove(os.path.join(diff_dir, TAR_NAME))

    return CHANGES_CAPTURED
# pylint: enable=too-many-locals
