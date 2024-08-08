<#
Hybrid-Notifications
https://github.com/markmburns/Hybrid-Notifications
mark_burns@dell.com
v2 - Silent alarm functionality to get through Focus Assist
v3 - 365 day scheduled task duration
v4 - 2 mins and hide notifications if wwahost is running always
v5 - remove wwahost as it's not 100% reliable and toast expiry
Display notifactions while device is hybrid joining, then restart at end
Toast notifications instead of full screen blocks
Speeds up hybrid join by triggering task
Scheduled tasks to run regularly === https://oofhours.com/2020/05/19/renaming-autopilot-deployed-hybrid-azure-ad-join-devices/
Scheduled task to display notifications to user === https://byteben.com/bb/deploy-service-announcement-toast-notifications-in-windows-10-with-memcm/
Custom protocol to restart device === https://www.imab.dk/windows-10-toast-notification-script/
Replacement for UserESP === https://docs.microsoft.com/en-us/troubleshoot/mem/intune/understand-troubleshoot-esp
Also recommend script to speed up AD Connect sync - https://github.com/markmburns/SyncNewAutopilotComputersToAAD
Win32 install cmd: powershell.exe -noprofile -executionpolicy bypass -file .\Hybrid-Notifications.ps1
Win32 uninstall: cmd.exe /c del %ProgramData%\Dell\Hybrid-Notifications\Hybrid-Notifications.ps1.tag
Win32 detection: %ProgramData%\Dell\Hybrid-Notifications\Hybrid-Notifications.ps1.tag
#>
#Parameters
param([string]$paramtitle, [string]$paramtext)

#Messages


#Functions
function Show-Notification {
    [cmdletbinding()]
    Param (
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline)]
        $ToastText,
        $RestartBoolean
    )
    #Check if ESP is running
    $ESPProcesses = Get-Process -Name 'wwahost' -ErrorAction 'SilentlyContinue'
    If ($ESPProcesses.Count -eq 0){
        Write-Host "WWAHost is not running - notify user"
        #notify user
    }else{
        Write-Host "WWAHost running"
        #return
    }
    If (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM") {
        #Created Scheduled Task to run as logged on user
        #Set Unique GUID for the Toast
        If (!($ToastGUID)) {
            $ToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
        }
        $Task_TimeToRun = (Get-Date).AddSeconds(30).ToString('s')
        $Task_Expiry = (Get-Date).AddSeconds(120).ToString('s')
        $Task_Action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $dest\Hybrid-Notifications.ps1 -paramtitle ""$ToastTitle"" -paramtext ""$ToastText"""
        $Task_Trigger = New-ScheduledTaskTrigger -Once -At $Task_TimeToRun
        $Task_Trigger.EndBoundary = $Task_Expiry
        $Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
        $Task_Settings = New-ScheduledTaskSettingsSet -Compatibility V1 -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600) -AllowStartIfOnBatteries
        $New_Task = New-ScheduledTask -Description "User_Toast_Notification_$ToastGUID Task for user notification. Title: $($ToastTitle) :: Text:$($ToastText) " -Action $Task_Action -Principal $Task_Principal -Trigger $Task_Trigger -Settings $Task_Settings
        Write-Host "Attempting to create user scheduled task with title: $ToastTitle and text: $ToastText"
        Register-ScheduledTask -TaskName "User_Toast_Notification_$ToastGUID" -InputObject $New_Task
    }else{
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
        $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $RawXml = [xml] $Template.GetXml()
	
	# Alarm to get through focus assist
        $scenario = $RawXml.CreateAttribute("scenario")
        $scenario.Value = "alarm"
        $audio = $RawXml.CreateElement("audio")
        $silent = $RawXml.CreateAttribute("silent")
        $silent.Value = "true"
        $audio.Attributes.Append($silent) > $null
        $toast = $RawXml.SelectSingleNode("toast")
        $toast.Attributes.Append($scenario) > $null
        $toast.AppendChild($audio) > $null # new audio element
	
        ($RawXml.toast.visual.binding.text|Where-Object {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
        ($RawXml.toast.visual.binding.text|Where-Object {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) > $null
     
        $actions = $RawXml.CreateElement("actions")
        $action2 = $RawXml.CreateElement("action")
        $button2Type = $RawXml.CreateAttribute("activationType")
        $button2Type.Value = "system"
        $button2Arguments = $RawXml.CreateAttribute("arguments")
        $button2Arguments.Value = "dismiss"
        $button2Content = $RawXml.CreateAttribute("content")
        $button2Content.Value = "Dismiss"
        $action2.Attributes.Append($button2Type) > $null
        $action2.Attributes.Append($button2Arguments) > $null
        $action2.Attributes.Append($button2Content) > $null
            

        If($RestartBoolean){
            Write-Host "Adding restart/dismiss buttons"
            $action1 = $RawXml.CreateElement("action")
            $button1Type = $RawXml.CreateAttribute("activationType")
            $button1Type.Value = "protocol"
            $button1Arguments = $RawXml.CreateAttribute("arguments")
            $button1Arguments.Value = "ToastReboot:"
            $button1Content = $RawXml.CreateAttribute("content")
            $button1Content.Value = "Restart"

            $action1.Attributes.Append($button1Type) > $null
            $action1.Attributes.Append($button1Arguments) > $null
            $action1.Attributes.Append($button1Content) > $null

            $actions.AppendChild($action1) > $null
        }
        $actions.AppendChild($action2) > $null
        $RawXml.DocumentElement.AppendChild($actions) > $null
	
        Write-Host $RawXml.OuterXml
        $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $SerializedXml.LoadXml($RawXml.OuterXml)

        $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
        $Toast.Tag = "PowerShell"
        $Toast.Group = "PowerShell"
        If($RestartBoolean){
            $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(120)
        }else{
            $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(2)
        }

        $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("PowerShell")
        $Notifier.Show($Toast);
    }
}

Function Write-ToastReboot{
    #Build out registry for custom action for rebooting the device via the action button
    try {
        #HKCR
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -erroraction silentlycontinue | out-null
        $ToastProtocol = get-item 'HKCR:\ToastReboot' -erroraction 'silentlycontinue'
        if (!$ToastProtocol) {
            Write-Host "Writing ToastReboot protocol to HKCR"
            New-item 'HKCR:\ToastReboot' -force | out-null
            set-itemproperty 'HKCR:\ToastReboot' -name '(DEFAULT)' -value 'url:ToastReboot' -force | out-null
            set-itemproperty 'HKCR:\ToastReboot' -name 'URL Protocol' -value '' -force | out-null
            new-itemproperty -path 'HKCR:\ToastReboot' -propertytype dword -name 'EditFlags' -value 2162688 | out-null
            New-item 'HKCR:\ToastReboot\Shell\Open\command' -force | out-null
            set-itemproperty 'HKCR:\ToastReboot\Shell\Open\command' -name '(DEFAULT)' -value 'C:\Windows\System32\shutdown.exe -r -t 00' -force | out-null
        }

    }
    catch {
        Write-Host "Failed to create the ToastReboot custom protocol in HKCR. Action button might not work"
        $ErrorMessage = $_.Exception.Message
        Write-Host "Error message: $ErrorMessage"
    }
}

#If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy bypass -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

#Tag file
if (-not (Test-Path "$($env:ProgramData)\Dell\Hybrid-Notifications"))
{
    $firstrun = 1
    Mkdir "$($env:ProgramData)\Dell\Hybrid-Notifications"
}
if (-not (Test-Path "$($env:ProgramData)\Dell\Hybrid-Notifications\Hybrid-Notifications.ps1.tag")){
    Set-Content -Path "$($env:ProgramData)\Dell\Hybrid-Notifications\Hybrid-Notifications.ps1.tag" -Value "Installed"
}

#Logging
$dest = "$($env:ProgramData)\Dell\Hybrid-Notifications"
if (-not (Test-Path $dest))
{
    mkdir $dest
}
Start-Transcript "$dest\Hybrid-Notifications.log" -Append

#Ensure users have access to log file
$acl = Get-Acl -path $dest\Hybrid-Notifications.log
$identity = "BUILTIN\Users"
$filesystemrights = "FullControl"
$type = "Allow"
$fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
$fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
$acl.SetAccessRule($fileSystemAccessRule)
Set-Acl -Path $dest\Hybrid-Notifications.log -AclObject $acl
Write-ToastReboot
Write-Host "User: "([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
If($paramtitle -and $paramtext){
    Write-Host "Title $paramtitle and text $paramtext were provided, skipping directly to toast notification"
    if($paramtext -like "*restart*"){
        Write-Host "With restart"
        Show-Notification -ToastTitle $paramtitle -ToastText $paramtext -RestartBoolean True
    }else{
        Write-Host "Without restart"
        Show-Notification -ToastTitle $paramtitle -ToastText $paramtext
    }
    Stop-Transcript
    Exit 0
}
#Check join status
$dsregcmdstatus = dsregcmd /status
$existingTask = Get-ScheduledTask -TaskName "Hybrid-Notifications" -ErrorAction SilentlyContinue

If($dsregcmdstatus -like "*AzureAdJoined : YES*" -and $dsregcmdstatus -like "*DomainJoined : NO*"){
    Write-Host "AAD joined"
    Stop-Transcript
    Exit 0
}ElseIf($dsregcmdstatus -like "*AzureAdJoined : YES*" -and $dsregcmdstatus -like "*DomainJoined : YES*"){
    Write-Host "Hybrid joined"
    If($null -eq $existingTask){
        Write-Host "Hybrid joined and no existing task. Assuming we can just quit"
        Stop-Transcript
        Exit 0
    }else{
        Write-Host "Hybrid joined and existing scheduled task - notify user, delete scheduled task, reboot"
        #Notify user
        Show-Notification -ToastTitle "Hybrid Join Notifications" -ToastText "Hybrid join process complete on $env:computername, a restart is recommended" -RestartBoolean True
        Disable-ScheduledTask -TaskName "Hybrid-Notifications" -ErrorAction Ignore
        Unregister-ScheduledTask -TaskName "Hybrid-Notifications" -Confirm:$false -ErrorAction Ignore
        Write-Host "Scheduled task unregistered"
        #trigger reboot
    }   
}else{
    Write-Host "Not yet hybrid-joined"
    $AutomaticDeviceJoinTask = Get-ScheduledTask -TaskName "Automatic-Device-Join" -ErrorAction SilentlyContinue
    If($null -ne $AutomaticDeviceJoinTask){
        Write-Host "Starting Automatic-Device-Join task"
        $AutomaticDeviceJoinTask | Start-ScheduledTask
    }
    Show-Notification -ToastTitle "Hybrid Join Notifications" -ToastText "$env:computername has not yet completed hybrid join process, functionality will be reduced e.g. account sync notifications, SSO access, OneDrive & Company Portal login"
    If($null -ne $existingTask){
        Write-Host "Scheduled task already exists - can exit now"
        Stop-Transcript
        Exit 0
    }
    #Copy script
    If (-not (Test-Path "$dest\Hybrid-Notifications.ps1")){
        Write-Host "Copying script to $dest"
        Copy-Item $PSCommandPath "$dest\Hybrid-Notifications.ps1"
    }
    #Create scheduled task
    $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy bypass -WindowStyle Hidden -File $dest\Hybrid-Notifications.ps1"
    #Create the scheduled tsak trigger
    $timespan = New-Timespan -minutes 2
    $triggers = @()
    $triggers += New-ScheduledTaskTrigger -Once -At 1am -RepetitionDuration  (New-TimeSpan -Days 365)  -RepetitionInterval  (New-TimeSpan -Minutes 2)
    #Register the scheduled task
    Register-ScheduledTask -User SYSTEM -Action $action -Trigger $triggers -TaskName "Hybrid-Notifications" -Description "Hybrid-Notifications" -Force
    Write-Host "Main scheduled task created."
}
Stop-Transcript
Exit 0