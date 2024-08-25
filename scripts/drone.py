# Credit: Connor Fancy

import paramiko
from scripts.logging_config import log
import threading
class Drone:
    """
    Represents a remote drone used for SSH communication and file transfer.

    The class establishes an SSH connection upon instantiation if a connection doesn't already exist.
    It provides methods to download files from the drone, upload files to the drone, and execute commands on the drone.
    The class utilizes the `paramiko` library for SSH functionality.
    The connection is stored as a class attribute to allow reuse across instances.

    """

    ssh = None  # class attribute to store the SSH connection

    def __init__(self, hostname, username, password):
        """
        Initialize the Drone object and establish an SSH connection if needed.

        Parameters:
        - hostname: The hostname or IP address of the drone.
        - username: The username for the SSH connection.
        - password: The password for the SSH connection.

        """
        try:
            if not Drone.ssh:  # if no SSH connection exists, create one
                Drone.ssh = paramiko.SSHClient()
                Drone.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # Drone.ssh.connect(hostname=hostname, username=username, password=password)
                Drone.ssh.connect(
                    hostname=hostname, username=username, password=password,
                    allow_agent=False, look_for_keys=False, banner_timeout=200 # This seems to be needed in some edge cases for now but if we ever go key-based we will need to remove it.
                )
                Drone.ssh.exec_command('export TERM=xterm')

        except Exception as e:
            print(f"Can't connect to the drone, do you have the VPN connection enabled?\n{e}")
            exit()

    def execute(self, cmd, stream_output=False):
        """
        Execute a command on the drone.

        Parameters:
        - cmd: The command to execute on the drone.
        - stream_output: If True, the output of the command is printed to the console in real-time.

        Returns:
        - output: The output of the command execution.

        """
        channel = Drone.ssh.get_transport().open_session()
        channel.exec_command(cmd)

        def streamer():
            while not channel.exit_status_ready():
                if channel.recv_ready():
                    output = channel.recv(4096).decode()
                    if stream_output:
                        print(output, end="")
                    yield output

        output_generator = streamer()

        # If we want to stream the output, we'll use a thread
        if stream_output:
            output_list = []

            def threaded_streamer():
                for out_chunk in output_generator:
                    output_list.append(out_chunk)

            thread = threading.Thread(target=threaded_streamer)
            thread.start()
            thread.join()
            output = "".join(output_list)
        else:
            output = "".join(list(output_generator))
            
        output = output.strip()
        err = channel.recv_stderr(4096).decode()
        if err != "" and "TERM" not in err:
            log.error(err)

        return output

    def download(self, remote_file, local_file):
        """
        Download a file from the drone to the local machine.

        Parameters:
        - remote_file: The path of the file on the drone.

        Returns:
        - local_file: The path of the downloaded file on the local machine.

        """

        try:
            sftp = Drone.ssh.open_sftp()
            sftp.get(remote_file, local_file)
            sftp.close()

        except Exception as e:
            log.error(e)
            self.close()
            exit()

    def upload(self, local_file):
        """
        Upload a file from the local machine to the drone.

        Parameters:
        - local_file: The path of the file on the local machine.

        Returns:
        - remote_file: The path of the uploaded file on the drone.

        """

        remote_file = "/tmp/" + local_file
        try:
            # upload
            sftp = Drone.ssh.open_sftp()
            sftp.put(local_file, remote_file)
            sftp.close()
            return remote_file

        except Exception as e:
            log.error(e)
            self.close()
            exit()


    def close(self):
        """
        Close the SSH connection to the drone.

        This method is left empty as the SSH connection should not be closed within the class.
        Closing the connection is the responsibility of the caller.

        """
        pass
