<#
.SYNOPSIS
This script is run from the system context to generate a toast notificatio in the logged in users context.

.DESCRIPTION
This script is run from the system context to generate a toast notificatio in the logged in users context.  It uses
portions of the PSADT to discover the logged on user and create a scheduled task that will run in the user's context.
The parameters define the content of the toast.  However, the images are baked into the script and would have to be 
changed in the script.

.PARAMETER HeaderText
The header text is the text next to the logo.  This could be similar to a from tag.

.PARAMETER TitleText
This is the heading first line in the toast notification.  Sort of like the subject line.

.PARAMETER BodyText1
This is the first paragraph in the body of the toast and is a required fielt.

.PARAMETER BodyText2
This is the second paragraph in the body of the toast and is not required.

.PARAMETER AlertTime
This is like the Sent time in an email, just in case the toast is sitting on the computer for hours.

.PARAMETER Expiration
This is the date/time that the toast will no longer display after and is an optional field.  So, if something is very
time sensitive and you don't want it to deliver more than an hour after it has been sent, this can be used to confirm
that will happen.

.PARAMETER Scenario
Possible values are: reminder | short | long
How long displayed:
--Reminder: Until Dismissed
--Short: 5 seconds
--Long: 25 seconds 

.PARAMETER DismissButtonText
This is the text that is displayed in the single button at the bottom of the toast message. Dismiss is the default text.

.NOTES
VERSION: 1.3 - Added simple file based detection method at end of script.
VERSION: 1.2 - Changed Date format to UK.
VERSION: 1.1 - Added new Heroimage & logoimage as base64 code. 
VERSION: 1.0 - Script created. 

.NOTES
This script is forked from a script created by Paul Wetter and will continue to evolve as I work to get it to meet my needs.
	NAME: Invoke-ToastAsUser.ps1
	    Based on content from the PowerShell App Deployment Toolkit (https://psappdeploytoolkit.com)
	LASTEDIT: 6th January 2022
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String]
    $HeaderText = 'Important Information: Global Protect Upgrade.',
    [Parameter(Mandatory = $false)]
    [String]
    $TitleText = 'Upgrading to the latest version of Global Protect.',
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText1 = 'Your device has been upgraded to the latest version of the global protect client, should you encounter any issues please contact the IT Service Desk.',
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText2,
    #Format 'dd/MM/yy @ hh:mm tt'
    [Parameter(Mandatory = $false)]
    [String]
    $AlertTime = (Get-Date -Format 'dd/MM @ hh:mm tt'),
    #Format 'dd/MM/yy or dd/MM/yyyy @ hh:mm tt'
    [Parameter(Mandatory = $false)]
    [String]
    $Expiration,
    #Scenario Possible values are: reminder | short | long --- How long displayed::: Reminder: Until Dismissed, Short: 5 seconds, Long: 25 seconds 
    [Parameter(Mandatory = $false)]
    [String]
    $Scenario = 'Reminder',
    [Parameter(Mandatory = $false)]
    [String]
    $DismissButtonText = 'Dismiss'
)

#If the Expiration variable has been defined and is a Date/Time, then check if the current time is beyond the exipiration time.
If (![string]::IsNullOrEmpty($Expiration)){
    Try {
        $ExpireDate = Get-Date $Expiration -ErrorAction Stop
        if ($ExpireDate -lt (Get-Date)){
            Exit
        }
    }
    Catch{}
}


Function Invoke-ProcessAsUser {
    <#
    .SYNOPSIS
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
    .DESCRIPTION
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
    .PARAMETER UserName
        Logged in Username under which to run the process from. Default is: The active console user. If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.
    .PARAMETER Path
        Path to the file being executed.
    .PARAMETER Parameters
        Arguments to be passed to the file being executed.
    .PARAMETER SecureParameters
        Hides all parameters passed to the executable from the Toolkit log file.
    .PARAMETER RunLevel
        Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:
        - HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value.
        - LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges.
    .PARAMETER Wait
        Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false.
    .PARAMETER PassThru
        Returns the exit code from this function or the process launched by the scheduled task.
    .PARAMETER WorkingDirectory
        Set working directory for the process.
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is $true.
    .EXAMPLE
        Execute-ProcessAsUser -UserName 'CONTOSO\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by specifying a username under which to execute it.
    .EXAMPLE
        Execute-ProcessAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by using the default active logged in user that was detected when the toolkit was launched.
    .NOTES
    .LINK
        http://psappdeploytoolkit.com
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$UserName = $RunAsActiveUser.NTAccount,
            [Parameter(Mandatory=$true)]
            [ValidateNotNullorEmpty()]
            [string]$Path,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$Parameters = '',
            [Parameter(Mandatory=$false)]
            [switch]$SecureParameters = $false,
            [Parameter(Mandatory=$false)]
            [ValidateSet('HighestAvailable','LeastPrivilege')]
            [string]$RunLevel = 'HighestAvailable',
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [switch]$Wait = $false,
            [Parameter(Mandatory=$false)]
            [switch]$PassThru = $false,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [string]$WorkingDirectory,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [boolean]$ContinueOnError = $true
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            [string]$executeAsUserTempPath = Join-Path -Path $dirAppDeployTemp -ChildPath 'ExecuteAsUser'
            [string]$exeSchTasks = Join-Path -Path ${ENV:windir} -ChildPath 'System32\schtasks.exe' # Manages Scheduled Tasks
        }
        Process {
            ## Initialize exit code variable
            [int32]$executeProcessAsUserExitCode = 0

            ## Confirm that the username field is not empty
            If (-not $UserName) {
                [int32]$executeProcessAsUserExitCode = 60009
                Write-Verbose -Message "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
                If (-not $ContinueOnError) {
                    Throw "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
                }
                Return
            }

            ## Confirm if the toolkit is running with administrator privileges
            If (($RunLevel -eq 'HighestAvailable') -and (-not $IsAdmin)) {
                [int32]$executeProcessAsUserExitCode = 60003
                Write-Verbose -Message "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
                If (-not $ContinueOnError) {
                    Throw "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
                }
                Return
            }

            ## Check whether the specified Working Directory exists
            If ($WorkingDirectory -and (-not (Test-Path -LiteralPath $WorkingDirectory -PathType 'Container'))) {
                Write-Verbose -Message "The specified working directory does not exist or is not a directory. The scheduled task might not work as expected."
            }

            ## Build the scheduled task XML name
            [string]$schTaskName = "ITAlert-ExecuteAsUser"
    
            ##  Remove and recreate the temporary folder
            If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
                Write-Verbose -Message "Previous [$executeAsUserTempPath] found. Attempting removal."
                Remove-Item -LiteralPath $executeAsUserTempPath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
            Write-Verbose -Message "Creating [$executeAsUserTempPath]."
            Try {
                $null = New-Item -Path $executeAsUserTempPath -ItemType 'Directory' -ErrorAction 'Stop'
            }
            Catch {
                Write-Verbose -Message "Unable to create [$executeAsUserTempPath]. Possible attempt to gain elevated rights."
            }

            ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
            If (((Split-Path -Path $Path -Leaf) -like 'PowerShell*') -or ((Split-Path -Path $Path -Leaf) -like 'cmd*')) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Preparing a vbs script that will start [$Path] (Parameters Hidden) as the logged-on user [$userName] silently..."
                }
                Else {
                    Write-Verbose -Message "Preparing a vbs script that will start [$Path $Parameters] as the logged-on user [$userName] silently..."
                }
                # Permit inclusion of double quotes in parameters
                $QuotesIndex = $Parameters.Length - 1
                If ($QuotesIndex -lt 0) {
                    $QuotesIndex = 0
                }
    
                If ($($Parameters.Substring($QuotesIndex)) -eq '"') {
                    [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`n", ';' -replace "`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$', '') + ' & chr(34)' }
                Else {
                    [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`n", ';' -replace "`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$','') + '"' }
                [string[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
                $executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
                $executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
                $executeProcessAsUserScript += 'WScript.Quit intReturn'
                $executeProcessAsUserScript | Out-File -FilePath "$executeAsUserTempPath\$($schTaskName).vbs" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
                $Path = "${ENV:WinDir}\System32\wscript.exe"
                $Parameters = "`"$executeAsUserTempPath\$($schTaskName).vbs`""
                Start-Sleep -Seconds 5
                try {
                    #Set-ItemPermission -Path "$executeAsUserTempPath\$schTaskName.vbs" -User $UserName -Permission 'Read'
                }
                catch {
                    Write-Verbose -Message "Failed to set read permissions on path [$executeAsUserTempPath\$schTaskName.vbs]. The function might not be able to work correctly."
                }
            }
            ## Prepare working directory insert
            [string]$WorkingDirectoryInsert = ""
            If ($WorkingDirectory) {
                $WorkingDirectoryInsert = "`n	  <WorkingDirectory>$WorkingDirectory</WorkingDirectory>"
            }
            ## Specify the scheduled task configuration in XML format
            [string]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo />
    <Triggers />
    <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
        <StopOnIdleEnd>false</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
    </Settings>
    <Actions Context="Author">
    <Exec>
        <Command>$Path</Command>
        <Arguments>$Parameters</Arguments>$WorkingDirectoryInsert
    </Exec>
    </Actions>
    <Principals>
    <Principal id="Author">
        <UserId>$UserName</UserId>
        <LogonType>InteractiveToken</LogonType>
        <RunLevel>$RunLevel</RunLevel>
    </Principal>
    </Principals>
</Task>
"@
            ## Export the XML to file
            Try {
                #  Specify the filename to export the XML to
                [string]$xmlSchTaskFilePath = "$dirAppDeployTemp\$schTaskName.xml"
                [string]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
                #Set-ItemPermission -Path $xmlSchTaskFilePath -User $UserName -Permission 'Read'
            }
            Catch {
                [int32]$executeProcessAsUserExitCode = 60007
                Write-Verbose -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]."
                If (-not $ContinueOnError) {
                    Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
                }
                Return
            }
            ## Create Scheduled Task to run the process with a logged-on user account
            If ($Parameters) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Creating scheduled task to run the process [$Path] (Parameters Hidden) as the logged-on user [$userName]..."
                }
                Else {
                    Write-Verbose -Message "Creating scheduled task to run the process [$Path $Parameters] as the logged-on user [$userName]..."
                }
            }
            Else {
                Write-Verbose -Message "Creating scheduled task to run the process [$Path] as the logged-on user [$userName]..."
            }
            $schTaskResult = Start-Process -FilePath $exeSchTasks -ArgumentList "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -WindowStyle Hidden -PassThru
            If ($schTaskResult.ExitCode -ne 0) {
                Write-Verbose -Message 'Try to see if it exists from a query. may not trigger the right one.'
                If ([string]::IsNullOrEmpty((schtasks.exe /query| Where-Object {$_ -like "*$schTaskNam*"}))){
                    [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
                    Write-Verbose -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]. [$($schTaskResult.ExitCode)]"
                    If (-not $ContinueOnError) {
                        Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]."
                    }
                    Return
                } else {
                    Write-Verbose -Message 'Try to see if it exists from a query. may not trigger the right one.'
                }
            }

            ## Trigger the Scheduled Task
            If ($Parameters) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] (Parameters Hidden) as the logged-on user [$userName]..."
                }
                Else {
                    Write-Verbose -Message "Trigger execution of scheduled task with command [$Path $Parameters] as the logged-on user [$userName]..."
                }
            }
            Else {
                Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] as the logged-on user [$userName]..."
            }
            Try {
                Start-ScheduledTask -TaskName $schTaskName -ErrorAction Stop
            }
            Catch {
                Write-Verbose -Message "Failed to trigger scheduled task [$schTaskName]."
                #  Delete Scheduled Task
                Write-Verbose -Message 'Delete the scheduled task which did not trigger.'
                Start-Process -FilePath $exeSchTasks -ArgumentList "/delete /tn $schTaskName /f" -WindowStyle Hidden
                If (-not $ContinueOnError) {
                    Throw "Failed to trigger scheduled task [$schTaskName]."
                }
                Return
            }
    
            ## Wait for the process launched by the scheduled task to complete execution
            If ($Wait) {
                Write-Verbose -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)..."
                Start-Sleep -Seconds 1
                Try {
                    [__comobject]$ScheduleService = New-Object -ComObject 'Schedule.Service' -ErrorAction Stop
                    $ScheduleService.Connect()
                    $RootFolder = $ScheduleService.GetFolder('\')
                    $Task = $RootFolder.GetTask("$schTaskName")
                    # Task State(Status) 4 = 'Running'
                    While ($Task.State -eq 4) {
                        Start-Sleep -Seconds 5
                    }
                    #  Get the exit code from the process launched by the scheduled task
                    [int32]$executeProcessAsUserExitCode = $Task.LastTaskResult
                }
                Catch {
                    Write-Verbose -Message "Failed to retrieve information from Task Scheduler."
                }
                Finally {
                    Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService) } Catch { }
                }
                Write-Verbose -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]."
            }
            Else {
                Start-Sleep -Seconds 1
            }

            ## Delete scheduled task
            Try {
                Write-Verbose -Message "Delete scheduled task [$schTaskName]."
                Start-Process -FilePath $exeSchTasks -ArgumentList "/delete /tn $schTaskName /f" -WindowStyle Hidden -ErrorAction 'Stop'
            }
            Catch {
                Write-Verbose -Message "Failed to delete scheduled task [$schTaskName]."
            }

    
            ## Remove the XML scheduled task file
            If (Test-Path -LiteralPath $xmlSchTaskFilePath -PathType 'Leaf') {
                Remove-Item -LiteralPath $xmlSchTaskFilePath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
    
            ##  Remove the temporary folder
            If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
                Remove-Item -LiteralPath $executeAsUserTempPath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
        }
        End {
            If ($PassThru) { Write-Output -InputObject $executeProcessAsUserExitCode }
        }
}


Function Get-LoggedOnUser {
<#
.SYNOPSIS
    Get session details for all local and RDP logged on users.
.DESCRIPTION
    Get session details for all local and RDP logged on users using Win32 APIs. Get the following session details:
        NTAccount, SID, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession, IsActiveUserSession
        IsRdpSession, IsLocalAdmin, LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber
.EXAMPLE
    Get-LoggedOnUser
.NOTES
    Description of ConnectState property:
    Value		 Description
    -----		 -----------
    Active		 A user is logged on to the session.
    ConnectQuery The session is in the process of connecting to a client.
    Connected	 A client is connected to the session.
    Disconnected The session is active, but the client has disconnected from it.
    Down		 The session is down due to an error.
    Idle		 The session is waiting for a client to connect.
    Initializing The session is initializing.
    Listening 	 The session is listening for connections.
    Reset		 The session is being reset.
    Shadowing	 This session is shadowing another session.

    Description of IsActiveUserSession property:
    If a console user exists, then that will be the active user session.
    If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user.

    Description of IsRdpSession property:
    Gets a value indicating whether the user is associated with an RDP client session.
.LINK
    http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
    )
    Try {
        Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
    }
    Catch {
    }
}

function Add-PSADTCustom {
    <#
    .SYNOPSIS
        This function adds the custom C# code from the PSADT needed to get the logged on user.
    .DESCRIPTION
        In the PSADT, this code is loaded with other classes used by the toolkit.  I have trimmed 
        the C# down to only the code for the QueryUser class.
        Only load this once per powershell session or you will get errors returned.
    .EXAMPLE
        Add-PSADTCustom
    #>
    [CmdletBinding()]
    param ()
    $signature = @"
    using System;
    using System.Text;
    using System.Collections;
    using System.ComponentModel;
    using System.DirectoryServices;
    using System.Security.Principal;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Text.RegularExpressions;
    using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
    
    namespace PSADT
    {
        public class QueryUser
        {
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern IntPtr WTSOpenServer(string pServerName);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern void WTSCloseServer(IntPtr hServer);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr pBuffer, out int pBytesReturned);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr pSessionInfo, out int pCount);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern void WTSFreeMemory(IntPtr pMemory);
    
            [DllImport("winsta.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern int WinStationQueryInformation(IntPtr hServer, int sessionId, int information, ref WINSTATIONINFORMATIONW pBuffer, int bufferLength, ref int returnedLength);
    
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern int GetCurrentProcessId();
    
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern bool ProcessIdToSessionId(int processId, ref int pSessionId);
    
            public class TerminalSessionData
            {
                public int SessionId;
                public string ConnectionState;
                public string SessionName;
                public bool IsUserSession;
                public TerminalSessionData(int sessionId, string connState, string sessionName, bool isUserSession)
                {
                    SessionId = sessionId;
                    ConnectionState = connState;
                    SessionName = sessionName;
                    IsUserSession = isUserSession;
                }
            }
    
            public class TerminalSessionInfo
            {
                public string NTAccount;
                public string SID;
                public string UserName;
                public string DomainName;
                public int SessionId;
                public string SessionName;
                public string ConnectState;
                public bool IsCurrentSession;
                public bool IsConsoleSession;
                public bool IsActiveUserSession;
                public bool IsUserSession;
                public bool IsRdpSession;
                public bool IsLocalAdmin;
                public DateTime? LogonTime;
                public TimeSpan? IdleTime;
                public DateTime? DisconnectTime;
                public string ClientName;
                public string ClientProtocolType;
                public string ClientDirectory;
                public int ClientBuildNumber;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            private struct WTS_SESSION_INFO
            {
                public Int32 SessionId;
                [MarshalAs(UnmanagedType.LPStr)]
                public string SessionName;
                public WTS_CONNECTSTATE_CLASS State;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct WINSTATIONINFORMATIONW
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 70)]
                private byte[] Reserved1;
                public int SessionId;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                private byte[] Reserved2;
                public FILETIME ConnectTime;
                public FILETIME DisconnectTime;
                public FILETIME LastInputTime;
                public FILETIME LoginTime;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1096)]
                private byte[] Reserved3;
                public FILETIME CurrentTime;
            }
    
            public enum WINSTATIONINFOCLASS
            {
                WinStationInformation = 8
            }
    
            public enum WTS_CONNECTSTATE_CLASS
            {
                Active,
                Connected,
                ConnectQuery,
                Shadow,
                Disconnected,
                Idle,
                Listen,
                Reset,
                Down,
                Init
            }
    
            public enum WTS_INFO_CLASS
            {
                SessionId=4,
                UserName,
                SessionName,
                DomainName,
                ConnectState,
                ClientBuildNumber,
                ClientName,
                ClientDirectory,
                ClientProtocolType=16
            }
    
            private static IntPtr OpenServer(string Name)
            {
                IntPtr server = WTSOpenServer(Name);
                return server;
            }
    
            private static void CloseServer(IntPtr ServerHandle)
            {
                WTSCloseServer(ServerHandle);
            }
    
            private static IList<T> PtrToStructureList<T>(IntPtr ppList, int count) where T : struct
            {
                List<T> result = new List<T>();
                long pointer = ppList.ToInt64();
                int sizeOf = Marshal.SizeOf(typeof(T));
    
                for (int index = 0; index < count; index++)
                {
                    T item = (T) Marshal.PtrToStructure(new IntPtr(pointer), typeof(T));
                    result.Add(item);
                    pointer += sizeOf;
                }
                return result;
            }
    
            public static DateTime? FileTimeToDateTime(FILETIME ft)
            {
                if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
                {
                    return null;
                }
                long hFT = (((long) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
                return DateTime.FromFileTime(hFT);
            }
    
            public static WINSTATIONINFORMATIONW GetWinStationInformation(IntPtr server, int sessionId)
            {
                int retLen = 0;
                WINSTATIONINFORMATIONW wsInfo = new WINSTATIONINFORMATIONW();
                WinStationQueryInformation(server, sessionId, (int) WINSTATIONINFOCLASS.WinStationInformation, ref wsInfo, Marshal.SizeOf(typeof(WINSTATIONINFORMATIONW)), ref retLen);
                return wsInfo;
            }
    
            public static TerminalSessionData[] ListSessions(string ServerName)
            {
                IntPtr server = IntPtr.Zero;
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
    
                List<TerminalSessionData> results = new List<TerminalSessionData>();
    
                try
                {
                    server = OpenServer(ServerName);
                    IntPtr ppSessionInfo = IntPtr.Zero;
                    int count;
                    bool _isUserSession = false;
                    IList<WTS_SESSION_INFO> sessionsInfo;
    
                    if (WTSEnumerateSessions(server, 0, 1, out ppSessionInfo, out count) == 0)
                    {
                        throw new Win32Exception();
                    }
    
                    try
                    {
                        sessionsInfo = PtrToStructureList<WTS_SESSION_INFO>(ppSessionInfo, count);
                    }
                    finally
                    {
                        WTSFreeMemory(ppSessionInfo);
                    }
    
                    foreach (WTS_SESSION_INFO sessionInfo in sessionsInfo)
                    {
                        if (sessionInfo.SessionName != "Services" && sessionInfo.SessionName != "RDP-Tcp")
                        {
                            _isUserSession = true;
                        }
                        results.Add(new TerminalSessionData(sessionInfo.SessionId, sessionInfo.State.ToString(), sessionInfo.SessionName, _isUserSession));
                        _isUserSession = false;
                    }
                }
                finally
                {
                    CloseServer(server);
                }
    
                TerminalSessionData[] returnData = results.ToArray();
                return returnData;
            }
    
            public static TerminalSessionInfo GetSessionInfo(string ServerName, int SessionId)
            {
                IntPtr server = IntPtr.Zero;
                IntPtr buffer = IntPtr.Zero;
                int bytesReturned;
                TerminalSessionInfo data = new TerminalSessionInfo();
                bool _IsCurrentSessionId = false;
                bool _IsConsoleSession = false;
                bool _IsUserSession = false;
                int currentSessionID = 0;
                string _NTAccount = String.Empty;
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
                if (ProcessIdToSessionId(GetCurrentProcessId(), ref currentSessionID) == false)
                {
                    currentSessionID = -1;
                }
    
                // Get all members of the local administrators group
                bool _IsLocalAdminCheckSuccess = false;
                List<string> localAdminGroupSidsList = new List<string>();
                try
                {
                    DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + ServerName + ",Computer");
                    string localAdminGroupName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\')[1];
                    DirectoryEntry admGroup = localMachine.Children.Find(localAdminGroupName, "group");
                    object members = admGroup.Invoke("members", null);
                    string validSidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
                    foreach (object groupMember in (IEnumerable)members)
                    {
                        DirectoryEntry member = new DirectoryEntry(groupMember);
                        if (member.Name != String.Empty)
                        {
                            if (Regex.IsMatch(member.Name, validSidPattern))
                            {
                                localAdminGroupSidsList.Add(member.Name);
                            }
                            else
                            {
                                localAdminGroupSidsList.Add((new NTAccount(member.Name)).Translate(typeof(SecurityIdentifier)).Value);
                            }
                        }
                    }
                    _IsLocalAdminCheckSuccess = true;
                }
                catch { }
    
                try
                {
                    server = OpenServer(ServerName);
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientBuildNumber, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    int lData = Marshal.ReadInt32(buffer);
                    data.ClientBuildNumber = lData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientDirectory, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    string strData = Marshal.PtrToStringAnsi(buffer);
                    data.ClientDirectory = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.ClientName = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientProtocolType, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    Int16 intData = Marshal.ReadInt16(buffer);
                    if (intData == 2)
                    {
                        strData = "RDP";
                        data.IsRdpSession = true;
                    }
                    else
                    {
                        strData = "";
                        data.IsRdpSession = false;
                    }
                    data.ClientProtocolType = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    lData = Marshal.ReadInt32(buffer);
                    data.ConnectState = ((WTS_CONNECTSTATE_CLASS) lData).ToString();
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionId, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    lData = Marshal.ReadInt32(buffer);
                    data.SessionId = lData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer).ToUpper();
                    data.DomainName = strData;
                    if (strData != String.Empty)
                    {
                        _NTAccount = strData;
                    }
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.UserName = strData;
                    if (strData != String.Empty)
                    {
                        data.NTAccount = _NTAccount + "\\" + strData;
                        string _Sid = (new NTAccount(_NTAccount + "\\" + strData)).Translate(typeof(SecurityIdentifier)).Value;
                        data.SID = _Sid;
                        if (_IsLocalAdminCheckSuccess == true)
                        {
                            foreach (string localAdminGroupSid in localAdminGroupSidsList)
                            {
                                if (localAdminGroupSid == _Sid)
                                {
                                    data.IsLocalAdmin = true;
                                    break;
                                }
                                else
                                {
                                    data.IsLocalAdmin = false;
                                }
                            }
                        }
                    }
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.SessionName = strData;
                    if (strData != "Services" && strData != "RDP-Tcp" && data.UserName != String.Empty)
                    {
                        _IsUserSession = true;
                    }
                    data.IsUserSession = _IsUserSession;
                    if (strData == "Console")
                    {
                        _IsConsoleSession = true;
                    }
                    data.IsConsoleSession = _IsConsoleSession;
    
                    WINSTATIONINFORMATIONW wsInfo = GetWinStationInformation(server, SessionId);
                    DateTime? _loginTime = FileTimeToDateTime(wsInfo.LoginTime);
                    DateTime? _lastInputTime = FileTimeToDateTime(wsInfo.LastInputTime);
                    DateTime? _disconnectTime = FileTimeToDateTime(wsInfo.DisconnectTime);
                    DateTime? _currentTime = FileTimeToDateTime(wsInfo.CurrentTime);
                    TimeSpan? _idleTime = (_currentTime != null && _lastInputTime != null) ? _currentTime.Value - _lastInputTime.Value : TimeSpan.Zero;
                    data.LogonTime = _loginTime;
                    data.IdleTime = _idleTime;
                    data.DisconnectTime = _disconnectTime;
    
                    if (currentSessionID == SessionId)
                    {
                        _IsCurrentSessionId = true;
                    }
                    data.IsCurrentSession = _IsCurrentSessionId;
                }
                finally
                {
                    WTSFreeMemory(buffer);
                    buffer = IntPtr.Zero;
                    CloseServer(server);
                }
                return data;
            }
    
            public static TerminalSessionInfo[] GetUserSessionInfo(string ServerName)
            {
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
    
                // Find and get detailed information for all user sessions
                // Also determine the active user session. If a console user exists, then that will be the active user session.
                // If no console user exists but users are logged in, such as on terminal servers, then select the first logged-in non-console user that is either 'Active' or 'Connected' as the active user.
                TerminalSessionData[] sessions = ListSessions(ServerName);
                TerminalSessionInfo sessionInfo = new TerminalSessionInfo();
                List<TerminalSessionInfo> userSessionsInfo = new List<TerminalSessionInfo>();
                string firstActiveUserNTAccount = String.Empty;
                bool IsActiveUserSessionSet = false;
                foreach (TerminalSessionData session in sessions)
                {
                    if (session.IsUserSession == true)
                    {
                        sessionInfo = GetSessionInfo(ServerName, session.SessionId);
                        if (sessionInfo.IsUserSession == true)
                        {
                            if ((firstActiveUserNTAccount == String.Empty) && (sessionInfo.ConnectState == "Active" || sessionInfo.ConnectState == "Connected"))
                            {
                                firstActiveUserNTAccount = sessionInfo.NTAccount;
                            }
    
                            if (sessionInfo.IsConsoleSession == true)
                            {
                                sessionInfo.IsActiveUserSession = true;
                                IsActiveUserSessionSet = true;
                            }
                            else
                            {
                                sessionInfo.IsActiveUserSession = false;
                            }
    
                            userSessionsInfo.Add(sessionInfo);
                        }
                    }
                }
    
                TerminalSessionInfo[] userSessions = userSessionsInfo.ToArray();
                if (IsActiveUserSessionSet == false)
                {
                    foreach (TerminalSessionInfo userSession in userSessions)
                    {
                        if (userSession.NTAccount == firstActiveUserNTAccount)
                        {
                            userSession.IsActiveUserSession = true;
                            break;
                        }
                    }
                }
    
                return userSessions;
            }
        }
    }
"@
    [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -TypeDefinition $signature -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'        
}

#Region ITAlertScript
# This variable contains the contents of the script that will be written to the script that will generate the toast.
$InvokeITAlertToastContents = @'
$AlertConfig = Get-Content -Path "$PSScriptRoot\alertconfig.json" -ErrorAction Ignore | Out-String
If ([string]::IsNullOrEmpty($AlertConfig)){
    exit 3
}
$Config = ConvertFrom-Json -InputObject $AlertConfig
$Scenario = $Config.Scenario # 'Reminder' #Possible values are: reminder | short | long --- How long displayed::: Reminder: Until Dismissed, Short: 5 seconds, Long: 25 seconds 
$HeaderText = $Config.HeaderText #'Important message from IT...'
$AttributionText = $Config.AttributionText #'Notice Time: ' + (Get-Date -Format 'MM/dd/yyyy @ hh:mm tt')
$TitleText = $Config.TitleText #'IT Mail System Offline'
$BodyText1 = $Config.BodyText1 #"There currently is an outage with Microsoft's cloud services.  This is effecting access to email, MyApps, Sharepoint and various other online services."
$BodyText2 = $Config.BodyText2 #"Currently there is no estimated time to repair.  We will send an update via toast notice in 2 hours or email when repaired."
$DismissButtonContent = $Config.DismissButtonContent #'Dismiss' #'Acknowledged'

#Images
# Picture Base64
# Create the picture object from a base64 code - HeroImage.

$Picture_Base64 = "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"
$HeroImage = "$env:TEMP\ToastHeroImage.jpg"
[byte[]]$Bytes = [convert]::FromBase64String($Picture_Base64)
[System.IO.File]::WriteAllBytes($HeroImage,$Bytes)
# Picture Base64 end

# Picture Base64
# Create the picture object from a base64 code - BadgeImage.

$Picture1_Base64 = "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"
$LogoImage = "$env:TEMP\ToastLogoImage.jpg"
[byte[]]$Bytes = [convert]::FromBase64String($Picture1_Base64)
[System.IO.File]::WriteAllBytes($LogoImage,$Bytes)
# Picture Base64 end

[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text>$HeaderText</text>
        <text placement="attribution">$AttributionText</text>
        <group>
            <subgroup>
                <text hint-style="title" hint-wrap="true" >$TitleText</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText1</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText2</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
    </actions>
</toast>
"@

#$App = "Microsoft.SoftwareCenter.DesktopToasts"
$App = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $nul
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $nul

# Load the notification into the required format
$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($Toast.OuterXml)

[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
'@
#EndRegion ITAlertScript


Add-PSADTCustom
[Security.Principal.WindowsIdentity]$CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent()
[boolean]$IsAdmin = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544')
[psobject]$RunAsActiveUser = Get-LoggedOnUser | Where-Object { $_.IsActiveUserSession }
$dirAppDeployTemp = 'C:\Temp'
$Configs = [PSCustomObject]@{
    Scenario = "$Scenario";
    HeaderText = "$HeaderText";
    AttributionText = "Sent by the IT Service Desk: $AlertTime"
    TitleText = "$TitleText";
    BodyText1 = "$BodyText1";
    BodyText2 = "$BodyText2";
    DismissButtonContent = "$DismissButtonText";
    Expiration = $Expiration
}
ConvertTo-Json $Configs > "$dirAppDeployTemp\alertconfig.json"
$InvokeITAlertToastContents > $dirAppDeployTemp\Invoke-ITAlertToast.ps1

Invoke-ProcessAsUser -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Parameters "-ExecutionPolicy Bypass -NoProfile -File $dirAppDeployTemp\Invoke-ITAlertToast.ps1"


Start-Sleep -Seconds 10
Remove-Item -Path "$dirAppDeployTemp\Invoke-ITAlertToast.ps1"
Remove-Item -Path "$dirAppDeployTemp\alertconfig.json"

## Create Detection Method that Toast has run. 
$logfilespath = "C:\logfiles"
If(!(test-path $logfilespath))
{
      New-Item -ItemType Directory -Force -Path $logfilespath
}

New-Item -ItemType "file" -Path "c:\logfiles\toast-Date.txt"