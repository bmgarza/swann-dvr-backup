import requests
from requests.auth import HTTPDigestAuth
from datetime import datetime, date, timedelta
import json
import humanize
from os import path

class SwannAPI():
    csrfTokenKey: str = "X-csrftoken"

    def __init__(self, hostName: str, userName: str, password: str) -> None:
        self.hostName: str = hostName
        self.baseUrl: str = f"http://{self.hostName}"
        self.userName: str = userName
        self.password: str = password

        self.__session: requests.Session = requests.Session()
        self.__session.headers = {
            'Content-Type': 'application/json',
            "Connection": "keep-alive",
            "dnt": "1",
        }
        # NOTE: BMG (Apr. 29, 2023) The system that we are interacting with uses Digest authentication instead of basic
        # authentication. This is very important to keep in mind.
        self.auth = HTTPDigestAuth(self.userName, self.password)
        self.__loggedIn: bool = False

    # TODO: BMG (Apr. 29, 2023) Might be a good idea to try to get this destructor working at some point.
    # def __del__(self):
    #     self.__Logout()

    def GetURLEndpoint(self, APIEndpoint: str) -> str:
        return f"{self.baseUrl}/{APIEndpoint}"

    def GetURLEndpointWithTimestamp(self, APIEndpoint: str) -> str:
        currentApiDateString: str = datetime.now().strftime("%Y-%m-%d@%H:%M:%S")
        return self.GetURLEndpoint(f"{APIEndpoint}?{currentApiDateString}")

    def __GetAPIResponse(self, apiURL: str, payload: dict[str, any], headers: dict[str, str] | None = None) -> requests.Response:
        response = self.__session.post(apiURL, data=json.dumps(payload), headers=headers)

        if not response.ok:
            responseMessage = json.loads(response.text)
            errorKey = responseMessage["error_code"]
            raise Exception(f"There was an exception accessing API ({apiURL}): {SwannAPI.__error_code[errorKey]}")
        else:
            return response

    def __StreamAPIDownloadToFile(self, downloadTarget: str, expectedFileSize: int, apiURL: str, payload: dict[str, any], headers: dict[str, str] | None = None):
        print(f"Starting download of {humanize.naturalsize(expectedFileSize)}:")
        fileDownloadProgress: int = 0
        fileDownloadPercentageDelta: int = 10
        fileDownloadPercentage: int = fileDownloadPercentageDelta

        with self.__session.post(apiURL, data=json.dumps(payload), headers=headers, stream=True) as req:
            with open(downloadTarget, 'wb') as file:
                for chunk in req.iter_content(chunk_size=8192):
                    fileDownloadProgress += len(chunk)
                    # We want to only print out percentage process in increments of the delta defined, we subtract a bit
                    # from the value we are using for comparison to make sure that the floating point precision doesn't
                    # cause the 100% console print to occur twice.
                    if (float(fileDownloadProgress) / expectedFileSize * 100 - 0.1) > fileDownloadPercentage:
                        print(f"  Download Progress: {fileDownloadPercentage}%")
                        fileDownloadPercentage += fileDownloadPercentageDelta
                    file.write(chunk)

        print(f"  Download Progress: 100%")

    def __Login(self):
        loginUrl: str = self.GetURLEndpoint("API/Web/Login")
        payload = {"data":{"remote_terminal_info":"WEB,chrome"}}

        response = self.__session.post(loginUrl, data=json.dumps(payload), auth=self.auth)
        self.__session.headers[SwannAPI.csrfTokenKey] = response.headers[SwannAPI.csrfTokenKey]
        if response.ok:
            self.__loggedIn = True
        else:
            raise Exception("Unable to successfully login to the Device.")

    def __EnsureLogin(self):
        if not self.__loggedIn:
            self.__Login()

    def __Logout(self):
        if not self.__loggedIn:
            return

        currentApiDateString: str = datetime.now().strftime("%Y-%m-%d@%H:%M:%S")
        apiUrl: str = self.GetURLEndpoint(f"API/Web/Logout?{currentApiDateString}")
        payload = {"version":"1.0","data":{}}

        response = self.__GetAPIResponse(apiUrl, payload=payload)
        if response.ok:
            del self.__session.headers[SwannAPI.csrfTokenKey]
            return response
        else:
            raise Exception("Unable to successfully logout of the Device.")

    def GetChannelInfo(self) -> dict[str, str]:
        apiUrl: str = self.GetURLEndpointWithTimestamp(f"API/Login/ChannelInfo/Get")
        return json.loads(self.__GetAPIResponse(apiUrl, payload={}).text)

    def GetDeviceInfo(self) -> dict[str, str]:
        apiUrl: str = self.GetURLEndpointWithTimestamp(f"API/Login/DeviceInfo/Get")
        return json.loads(self.__GetAPIResponse(apiUrl, payload={}).text)

    def SearchPlaybackRecords(self, channelIndex: int, searchDate: date) -> dict[str, str]:
        self.__EnsureLogin()

        apiUrl: str = self.GetURLEndpointWithTimestamp(f"API/Playback/SearchRecord/Search")
        searchDateString: str = searchDate.strftime("%m/%d/%Y")
        # TODO: BMG (Apr. 25, 2023) There is a way of changing the record type to only get movement clips, it'll be
        # worth looking into that later.
        payload = {
            "version":"1.0",
            "data":{
                "channel": [f"CH{channelIndex}"],
                "start_date": searchDateString,
                "start_time": "00:00:00",
                "end_date": searchDateString,
                "end_time": "23:59:59",
                "record_type": 1, # This record type indicates that we are looking for "Normal video clips"
                # "record_type": 128, # This record type indicates that we are looking for "Intelligent video clips"
                "smart_region": [],
                "enable_smart_search": 0,
                "stream_mode": "Mainstream"
            }
        }

        # Any exception handling for the return is going to be handled by the GetAPIResponse function
        return json.loads(self.__GetAPIResponse(apiUrl, payload=payload).text)

    @staticmethod
    def __ValidateRecordField(recordOfInterest: dict[str, str], fieldName: str) -> str:
        if not fieldName in recordOfInterest:
            raise Exception(f"The field \"{fieldName}\" could not be found in the record provided: {json.dumps(recordOfInterest)}")
        else:
            return recordOfInterest[fieldName]

    @staticmethod
    def __ConvertDateAndTimeToDownloadTimeString(dateString: str, timeString: str) -> str:
        year: str = dateString[6:]
        month: str = dateString[0:2]
        day: str = dateString[3:5]
        return f"{year}{month}{day}{timeString.replace(':', '')}"

    def DownloadVideoFile(self, recordOfInterest: dict[str, str | int], downloadDir: str):
        self.__EnsureLogin()

        # The channel is given as a number instead of an index, we need to update that to fix it.
        channel: str        = self.__ValidateRecordField(recordOfInterest, "channel")
        channel_index: str  = int(channel[2:]) - 1
        # The steam of the channel can either be "Mainstream" or "Substream".
        stream_mode: str = self.__ValidateRecordField(recordOfInterest, "stream_mode")
        stream_type: str = "0" if (stream_mode == "Mainstream") else "1"
        # Record type is indicating whether this is a normal clip or one of the intelligent clips that were taken.
        record_type: str = self.__ValidateRecordField(recordOfInterest, "record_type")
        # Start and end times are passed through to the query by just mashing them together and removing ":" and "/"
        # characters.
        start_date: str             = self.__ValidateRecordField(recordOfInterest, "start_date")
        start_time: str             = self.__ValidateRecordField(recordOfInterest, "start_time")
        download_start_time: str    = self.__ConvertDateAndTimeToDownloadTimeString(start_date, start_time)
        end_date: str               = self.__ValidateRecordField(recordOfInterest, "end_date")
        end_time: str               = self.__ValidateRecordField(recordOfInterest, "end_time")
        download_end_time: str      = self.__ConvertDateAndTimeToDownloadTimeString(end_date, end_time)
        # I assume that the record ID and the disk event ID are used to identify the recording file that is going to be
        # used to create the file that is going to be downloaded.
        record_id: str      = self.__ValidateRecordField(recordOfInterest, "record_id")
        disk_event_id: str  = self.__ValidateRecordField(recordOfInterest, "disk_event_id")
        # Store the Size of the file that we are going to download to help with tracking download progress.
        size: int   = self.__ValidateRecordField(recordOfInterest, "size")

        downloadApiEndpoint: str = f"download.mp4?"
        downloadApiEndpoint += f"start_time={download_start_time}"
        downloadApiEndpoint += f"&end_time={download_end_time}"
        downloadApiEndpoint += f"&channel={channel_index}"
        downloadApiEndpoint += f"&record_type={record_type}"
        downloadApiEndpoint += f"&stream_type={stream_type}"
        downloadApiEndpoint += f"&record_id={record_id}"
        downloadApiEndpoint += f"&disk_event_id={disk_event_id}"
        downloadApiUrl = self.GetURLEndpoint(downloadApiEndpoint)

        downloadFilePath: str = f"{path.abspath(downloadDir)}/swann_{download_start_time}_{download_end_time}.mp4"
        self.__StreamAPIDownloadToFile(downloadFilePath, size, downloadApiUrl, {})

    __error_code: dict[str, str] = {
        "param_error": "The requested data is invalid!",
        "no_permission": "No permission",
        "first_login": "Please set password",
        "passwd_weak_login": "Weak password",
        "time_abnormal_login": "System time is abnormal, please change the password",
        "passwd_expired_login": "Password has expired. Please set it again",
        "passwd_expires_state": "password expires state",
        "save_failed": "Save Failed!",
        "search_failed": "Search Failed!",
        "device_play_locked": "The device is in playback mode, please try again later!",
        "pwd_weak_rule": "The password does not meet the requirements.",
        "current_pwd_error": "Incorrect password",
        "current_pwd_error_ntime": "The password has been entered incorrectly 5 times. Please try again in % seconds.",
        "session_invalid": "Session invalid",
        "network_error": "Network error",
        "data_error": "data error",
        "filename_error": "filename error",
        "file_error": "Error file!",
        "upgrade_failed": "upgrade failed!",
        "username_error": "User name error",
        "overreach": "Unauthorized",
        "short_modify_time": "The password change interval is too short.",
        "unmatched_pwd": "The two passwords do not match, please re-enter!",
        "pwd_empty": "Password cannot be empty!",
        "pwd_length_err": "The password length is not in line with the rules",
        "pwd_equal_name": "The password cannot be the same as the username or the username written backwards",
        "pwd_equal_old": "The new password cannot be the same as the previous two passwords",
        "pwd_repeated": "The new password and the old password must have two different characters",
        "part_failed": "The following channel parameters failed to save",
        "user_auth_failed": "Invalid username or password!",
        "net_unreachable_or_dns_wrong": "Network cannot access or DNS is incorrect!",
        "check_smtp_port": "Connect Error! Please check the SMTP PORT!",
        "tls_ssl_handshake_err": "TLS/SSL link error!",
        "email_connect_err": "Connection error! Please check the recipient's email!",
        "not_modified": "No change!",
        "http_redirect_https": "HTTP turns HTTPS",
        "not_found": "not found",
        "method_not_allowed": "Request methods are not allowed!",
        "payload_too_large": "Data overload",
        "uri_too_long": "URI Too Long",
        "internal_server_error": "Internal server error",
        "install_failed": "Installation failed",
        "uninstall_failed": "Uninstall Failed",
        "uninstall_not_allow": "Uninstall is not allowed while in use",
        "switch_failed": "Certificate switch failed",
        "upload_failed": "Uninstall Failed",
        "upload_success": "Installation successful",
        "length_too_long": "The data is too big",
        "unsafe_siganature": "Unsafe certificate",
        "cert_key_not_match": "Certificate mismatch",
        "invalid_cert_time": "Invalid certificate time",
        "invalid_private_key": "Invalid private key file",
        "invalid_cert": "Invalid certificate file",
        "invalid_key_usage": "Invalid certificate key usage",
        "invalid_cert_chain": "Invalid certificate chain",
        "invalid_cacert": "Invalid root certificate",
        "invalid_cacert_time": "Contains an invalid root certificate",
        "token_generation_failed": "Token generation failed",
        "token_invalid": "Token invalid",
        "lack_memory": "Out of Memory",
        "no_need_upgrade": "Current version is up to date",
        "updating": "Upgrade in Progress",
        "in_user_interface": "Local User Operation in Progress, Cannot Start Upgrade!",
        "localuser_operating_cannot_talkback": "Local User Operation in Progress, Cannot Start Talkback!",
        "upgrade_memory_not_enough": "Out of Memory",
        "upgrade_file_error": "Error file!",
        "upgrade_parameter_error": "Error parameters",
        "upgrade_no_u_disc": "USB device not found",
        "upgrade_no_upgrade_software": "Current version is up to date",
        "upgrade_software_is_new": "Current version is up to date",
        "upgrade_software_packet_error": "Error file!",
        "upgrade_language_version_error": "Get device language error",
        "upgrade_file_name_too_long": "File name overlength",
        "upgrade_exit": "upgrade failed!",
        "upgrade_uncipher": "upgrade failed!",
        "upgrade_download_faild": "Download firmware failed",
        "upgrade_download_network_error": "Network not connected",
        "upgrade_environmentvar_different": "The software storage partition has been modified. Please use FAT32 USB flash disk to upgrade the device",
        "upgrade_usbtype_error": "upgrade failed!",
        "verify_failed": "Username or Password Error!",
        "login_block": "Account locked. Try again in -- seconds.",
        "login_failed_or_block": "Incorrect username or password, if you have tried many times, please try again after '-- minutes'",
        "login_failed_or_block_second": "Incorrect username or password, if you have tried many times, please try again after '-- seconds'",
        "black_ip": "The local IP address is forbidden.",
        "connect_server_err": "Connect Server Error!",
        "operation_failed": "Operation failure",
        "illegal_operation": "Please close __SMARTARR__",
        "no_login": "No login",
        "expired": "Login timeout. Log in again.",
        "one_IE": "Other users log in at this IP, the current user has been forced to go offline.",
        "logout": "Have to log out",
        "login_at_other": "The account is in use.",
        "device_reboot": "System restarting...",
        "passwd_expired": "Password expired, please login again to set!",
        "param_changed": "User parameters changed, please log in again!",
        "network_changed": "Network parameters changed, please log in again!",
        "ssl_error": "certificate expires.",
        "format_failed": "Formatting failed",
        "frequent_operation": "Operation Frequently",
        "check_ver_timeout": "Version detection timeout",
        "check_ver_error": "Unable To Find Latest Version",
        "get_packsize_failed": "Get upgrade package size failed",
        "upgrade_pack_toolarge": "Upgrade firmware oversize",
        "pack_download_fialed": "Upgrade pack download failed",
        "connect_error": "Network Connection Error!",
        "send_error": "Send Error",
        "reveive_error": "Receive error",
        "network_info_error": "Network information error",
        "connect_server_timeout": "Connect Server Timeout!",
        "user_authentication_failed": "User authentication failed",
        "send_request_timeout": "Send request to dyndns server timeout!",
        "ddns_server_response_timeout": "DDNS server response time out!",
        "host_name_abnormal": "Hostname exception",
        "domain_name_incomplete": "Incomplete domain name",
        "username_or_password_empty": "Invalid username or password!",
        "too_many_or_too_few_hosts_found": "Too many or too few hosts found!",
        "dns_service_error": "DDNS Service Error! Try 1 hour later!",
        "requested_ip_address_failed": "Request IP address Failed!",
        "unknown_error": "Unknown Error!",
        "cloud_video_upload_chn_limit": "The number of open channels for cloud video has reached the maximum. Please refresh the page or close the relevant buttons",
        "cloud_active_failed": "Get Authenticate Link Failure!",
        "handle_processed": "Error",
        "illegal_param": "Illegal parameter",
        "connect_failed": "Ftp connection failed",
        "login_failed": "Login failed",
        "write_file_failed": "Write failure",
        "created_dir_failed": "Creation failed",
        "system_error": "System error.",
        "connect_ip_server_timeout": "Connect IP Server Timeout!",
        "connect_ddns_server_timeout": "Connect DDNS Server Timeout!",
        "send_request_to_server_timeout": "Sending request to DDNS server timed out",
        "server_response_timeout": "Server response timed out!",
        "invalid_username_or_password": "Invalid username or password!",
        "hostname_not_exist": "Hostname does not exist!",
        "hostname_or_username_not_exist": "Hostname or username does not exist!",
        "hostname_blocked": "The host name exists but is locked!",
        "username_or_passwore_is_empty": "The username or password cannot be empty!",
        "not_donator_stop_update": "Not donator, update stopped !",
        "not_fully_qualified_domain_name": "Not a fully qualified Hostname!",
        "host_under_different_account": "The host exists but under a different account!",
        "modify_failed": "Modify Failed",
        "c23_pwd_check_failed": "1. 8~9 characters: combination should consist of at least 3 from uppercase letters, lowercase letters, numbers or special characters. 2. 10~15 characters: combination should consist of at least 2 from uppercase letters, lowercase letters, numbers or special characters. 3. Repeated and continuous characters exceed 4-digit are prohibited. i.e., 6666/bbbb or 1234/abcd. 4. Continuous keys of keyboard pattern exceed 4-digit are prohibited. i.e., qwer or ghjk",
        "data_saving_busy": "frequent operation, please try again later!",
        "network_port_conflict": "Port conflict, please replace the port!",
        "analog_chn_limit": "The number of analog channels supported by intelligent switch has reached the upper limit. Please refresh the page or close the relevant button",
        "file_invalid": "File error, please select a legal file!",
        "user_expired": "The main user information has been modified, please log in again",
        "ip_filter_list_empty": "Please add at least one enabled IP",
        "connet_close": "Device connection abnormal",
        "ver_err": "Upgrade file does not match",
        "not_exist": "Device is offline",
        "upgrading": "IPC equipment is being upgraded",
        "read_file_fail": "Error reading file",
        "upgradeFailed": "upgrade failed",
        "file_creation_error": "File creation error",
        "lack_channel": "No available channel to add more cameras",
        "no_heartbeat": "Connection timed out. Log in again!",
        "no_support": "no support",
        "default_failed": "Failed to restore default values",
        "device_busy": "The device is processing the maximum number of APIs",
        "user_expired_login": "User expired login",
        "user_locked_login": "User lock login",
        "netip_limited": "After the login IP is added to the blacklist",
        "forced_offline": "Force logout",
        "pwd_weak": "The modified IPC password has low complexity",
        "modify_failed_pwd_err": "Modifying IP user name or password error of IPC",
        "modify_failed_syntax_err": "Modifying IP syntax configuration error of IPC",
        "illegal_request": "Illegal request",
        "username_empty": "The user name is empty",
        "username_repeat": "repeat of user name",
        "username_invalid": "Only letters, numbers and underscores are allowed for the user name",
        "pwd_risk": "The password is weak",
        "service_unavailable_error": "Service not available",
        "ftp_close_failed": "Failed to shut down the FTP service",
        "Channel_limit": "More than max system channel num",
        "ipc_upgrading": "these ipc channels are being upgraded, please select again",
        "disk_changed": "Disk is changed!",
        "group_name_error": "The group name already exists, please modify",
        "user_error": "Please input a email user!",
        "bind_fail": "The device is already bind!",
        "unbind_fail": "The device isn't bind to any account!",
        "error_try_again": "An error has occurred. Please try again later.",
        "Network_or_DNS_error": "Network is unreachable or DNS is incorrect !",
        "latest_ver_not_find": "Unable To Find Latest Version",
        "no_data_in_time": "No data found, please adjust the time and try again!",
        "network_connection_overtime": "Network connection overtime.",
        "ddns_register_failed": "Your account is failed to register, please try again later.",
        "invalid_file": "Invalid upgrade file",
        "download_failed": "Download file failed",
        "file_already_exists": "File already exists",
        "file_size_exceeds_limit": "File size exceeds limit",
        "ipc_pwd_rule_tip1": "1. 8~9 characters: combination should consist of at least 3 from uppercase letters, lowercase letters, numbers or special characters.",
        "ipc_pwd_rule_tip2": "2. 10~15 characters: combination should consist of at least 2 from uppercase letters, lowercase letters, numbers or special characters.",
        "ipc_pwd_rule_tip3": "3. Repeated and continuous characters exceed 4-digit are prohibited. i.e., 6666/bbbb or 1234/abcd.",
        "ipc_pwd_rule_tip4": "4. Continuous keys of keyboard pattern exceed 4-digit are prohibited. i.e., qwer or ghjk",
        "cannot_upgrade": "There has no newer firmware available to upgrade.",
        "have_login": "Online client exceeds limit",
        "err_address_conflicting": "The address is used",
        "not_exist_necessary_params": "Not exist necessary params!",
        "id_or_password_error": "ID or password error!",
        "not_exist_data": "Not exist data!",
        "data_update_fail": "Data update fail!",
        "data_insert_fail": "Data insert fail!",
        "data_select_fail": "Data select fail!",
        "host_name_exit_unable_to_use": "Host name exit,unable to use!",
        "id_or_password_is_empty": "ID or password is empty!",
        "host_not_exit_able_to_use": "Host not exit,able to use!",
        "err_net_config_invalid": "The entered settings are incorrect! Check that the IP address, subnet mask, and default gateway are in the same segment of the subnet.",
        "file_formats_unsupported": "The file type is wrong!",
        "no_line_drawing": "Save failed! Please note the Rule Number(Detection Area) is not marked.",
        "need_close_tuya": "Need to close the Tuya!",
        "fd_pd_chn_limit": "__FD__ and __PD__ support the maximum number of channels",
        "target_detection_chn_limit": "The number of open channels for Target detection  has reached the maximum. Please refresh the page or close the relevant buttons",
        "email_must_verify": "The email address has changed, please re-verify the email address.",
        "email_verifycode_error": "Verification code error!",
        "preset_point_cruising": "Please stop the Cruise operation before using the PTZ setup!",
        "preset_point_empty": "Please add preset points",
        "part_group_failed": "The following group parameters failed to save",
        "http_listening_operation": "Please open Server Config ->Http Listening -> Enable",
        "err_filename_repeat": "The file name is duplicated, please change the file name",
        "disk_unavailable_for_upgrade": "No HDD is installed! It is allowed to upgrade the firmware only when there is at least one fully-functioning HDD installed."
    }

# if __name__ == "__main__":
#     dvr: SwannAPI = SwannAPI("192.168.1.180:85", "admin", "pemdas11894")
#     playbackRecords = dvr.SearchPlaybackRecords(1, date.today() - timedelta(days=1))
#     downloadRecord = playbackRecords["data"]["record"][0][0]
#     dvr.DownloadVideoFile(downloadRecord, "./")
