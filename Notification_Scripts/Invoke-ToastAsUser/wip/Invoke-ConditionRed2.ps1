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

.EXAMPLE
An example

.NOTES
	NAME: Invoke-ToastAsUser.ps1
	VERSION: 1.0
	AUTHOR: Paul Wetter
        Based on content from the PowerShell App Deployment Toolkit (https://psappdeploytoolkit.com)
	LASTEDIT: December 26, 2020
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String]
    $HeaderText = 'Important message from IT...',
    [Parameter(Mandatory = $true)]
    [String]
    $TitleText,
    [Parameter(Mandatory = $true)]
    [String]
    $BodyText1,
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText2,
    #Format 'MM/dd/yyyy @ hh:mm tt'
    [Parameter(Mandatory = $false)]
    [String]
    $AlertTime = (Get-Date -Format 'MM/dd/yyyy @ hh:mm tt'),
    #Format 'MM/dd/yyyy @ hh:mm tt'
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
                If ([string]::IsNullOrEmpty((schtasks.exe /query| where {$_ -like "*$schTaskNam*"}))){
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

$HeroImage = "${Env:Temp}\ToastHeroImage.gif"
$B64HeroImage = @"
R0lGODlhbAG0AMQfANkAAVsEBqkECYUCBcUBA+YCBS8BAvIlCRYWFhQAAMQGDdkRB40VGr4QFdkFCt4iEOQYDakRFsoPC80mHLIjIG8WGkoWGLcZGhoICPAyEC0SE/Q7
FxAPD9IAAAAAAP///yH/C05FVFNDQVBFMi4wAwEAAAAh/wtYTVAgRGF0YVhNUDw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlk
Ij8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQ4IDc5LjE2Mzg1OCwgMjAxOS8wMy8wNi0w
MzoxODozNiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlw
dGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAv
MS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhv
dG9zaG9wIEVsZW1lbnRzIDE4LjAgKFdpbmRvd3MpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOkUyNEQ2ODBDNEZGMjExRUJBODIyQzgyNUFGNEQ5NjYwIiB4bXBN
TTpEb2N1bWVudElEPSJ4bXAuZGlkOkUyNEQ2ODBENEZGMjExRUJBODIyQzgyNUFGNEQ5NjYwIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9Inht
cC5paWQ6RTI0RDY4MEE0RkYyMTFFQkE4MjJDODI1QUY0RDk2NjAiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6RTI0RDY4MEI0RkYyMTFFQkE4MjJDODI1QUY0RDk2
NjAiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz4B//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl
5OPi4eDf3t3c29rZ2NfW1dTT0tHQz87NzMvKycjHxsXEw8LBwL++vby7urm4t7a1tLOysbCvrq2sq6qpqKempaSjoqGgn56dnJuamZiXlpWUk5KRkI+OjYyLiomIh4aF
hIOCgYB/fn18e3p5eHd2dXRzcnFwb25tbGtqaWhnZmVkY2JhYF9eXVxbWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkFAPz49PDs6OTg3NjU0MzIxMC8uLSwrKikoJyYl
JCMiISAfHh0cGxoZGBcWFRQTEhEQDw4NDAsKCQgHBgUEAwIBAAAh+QQFBQAfACwAAAAAbAG0AAAF/6CGjGRpnmiqrmzrvnAsz3Rt33iu76zGecCgcEgsGo/IpHLJbDqf
0Kh0Sq1ar9gkB5Hter/gsHhMLpuRo7N6zW673/BvOk6v2+/4PHSu7/v/gIFZfIKFhoeIfYSJjI2Oj12LkJOUlZZAkpeam5yKXJ2BCaKgpIiZpW2iGBgGBgEBFbEWGgmo
o6h4p7hfoq2vrwPBDALExA0SEhEWtaAJFrEVv60Gt7tqutZSqr4BwcQK4AoO4w4A5uYd5sqlBgMSDuEKAhERA9EWrRjV2V7Y/EoJuHkz9m7cuYMHOyhM52AdKQMCChRA
SM5BA3r0GAx4ZUDfvyv+PgYJ6ApYBAHgCP90KIcQwMKXMBeqs8AuosuXCVdWVHBRY7R8zEQ2CZmtF7Bv4sbFXMp06cya6JrCPEcOXM+NQIUmIVoq4FGUFXNKHRvTXAOa
DwVEJVsWgEQA4xRk3DgLg1YiXDUlYHVUAQFyYtkKxgngLNSbg8fChQcuAoMAde96yDtpr6sBSAGvTcxZZmG0oCBu7sz0YNye0TTY/Ui5kdcBDBokPUe6dlvDaUfblkqV
p+Ofq3e1NuQ1AMrZuheq3J3YLOhOohEzF2zadwULHksNB/Qa5UqXyafbdn5YPGfw5sb1DKAa1HY93cW9dbncvHnyuaXbb54enmP2wVnyXh4JBNCAQeHtx9z/U7k5oOB4
/cnFwHUBQjJgHu2Io9+D931WHoe7ReiYBT9MciGBxpUD4n74habWhivy55YDDJBIyYko2hSjeC1C9+KOtYHX0DKV4KhHOwkCyVaPnESnZGfmKMCABpcYeeQAHUz0JJQe
5rflYGZVQGWVn3BSIAFafkldly4mqaZCcDVQQYU3lmmmcW6+mQ6bPub5JVzKlKiJlX9kCJ6epfHZ5I+IliXlc4PaGdoABPj5JJObONmoZxJMSQqh3FEKI6KYaqLppm4p
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
"@
[byte[]]$Bytes = [convert]::FromBase64String($B64HeroImage)
[System.IO.File]::WriteAllBytes($HeroImage,$Bytes)

$LogoImage = "${Env:Temp}\ToastLogoImage.jpg"
$B64LogoImage = @"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
"@
[byte[]]$Bytes = [convert]::FromBase64String($B64LogoImage)
[System.IO.File]::WriteAllBytes($LogoImage,$Bytes)

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
    AttributionText = "Notice Time: $AlertTime"
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