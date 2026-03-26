dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_image_name in ("wscript.exe", "powershell.exe", "cmd.exe", "ScreenConnect.ClientService.exe")
| filter actor_process_command_line contains "ZoomInstaller_Final.vbs"
   or actor_process_command_line contains "DesktopInstaller.vbs"
   or actor_process_command_line contains "ExecutionPolicy Bypass"
   or actor_process_command_line contains "WindowStyle Hidden"
   or actor_process_command_line contains "installer_55569.msi"
   or actor_process_command_line contains "ScreenConnect Client"
   or actor_process_command_line contains "labogz.com"
   or actor_process_command_line contains "Zone.Identifier"
   or actor_process_command_line contains "bot8306714610"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, causality_actor_process_image_name, action_file_sha256
| sort desc _time
