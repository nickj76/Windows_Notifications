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
    $HeaderText = 'Launch of the IT team notifications service.',
    [Parameter(Mandatory = $false)]
    [String]
    $TitleText = 'The IT team are improving the way we communicate with you.',
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText1 = 'From today, IT notices like this one will pop up your desktop to alert you to key software upgrades, service outages and PC hardware warnings.',
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText2 = "For more information about the service please visit the IT FAQs on SurreyNet.",
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
#$App = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
#$App = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
$App = "MSEdge"
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