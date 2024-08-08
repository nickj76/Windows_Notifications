<#
.SYNOPSIS
    Create a WIndows 10 toast notification.

.DESCRIPTION
    Everything is customisable through custom-message.xml.
    custom-message.xml can be locally or set to an UNC path with the -Config parameter.
    This way you can quickly modify the configuration without the need to push new files to the computer running the toast.
    
.PARAMETER Config
    Specify the path for the custom-message.xml. If none is specified, the script uses the local custom-message.xml

.NOTES
    Filename: Toast.ps1
    Version: 1.2
    
    Version history:

    1.1   -   Added links to required images
    1.0.1 -   Add Synopsis, Description, Paramenter, notes etc
    1.0   -   Script created

.LINK
    https://morethanpatches.com/
    https://poweronplatforms.com
#> 

[CmdletBinding()]
param(
    [Parameter(HelpMessage='Path to XML Configuration File')]
    [string]$Config
)

######### FUNCTIONS #########

# Create write log function
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        
        # EDIT with your location for the local log file
        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path="$env:APPDATA\ToastNotificationScript\Toast.log",

        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info"
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
		if ((Test-Path $Path)) {
			$LogSize = (Get-Item -Path $Path).Length/1MB
			$MaxLogSize = 5
		}
                
        # Check for file size of the log. If greater than 5MB, it will create a new one and delete the old.
        if ((Test-Path $Path) -AND $LogSize -gt $MaxLogSize) {
            Write-Error "Log file $Path already exists and file exceeds maximum file size. Deleting the log and starting fresh."
            Remove-Item $Path -Force
            $NewLogFile = New-Item $Path -Force -ItemType File
        }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (-NOT(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

# Create Get GivenName function
function Get-GivenName {
    Write-Log -Message "Running Get-GivenName function"
    # Thanks to Trevor Jones @ http://smsagent.blog

    Clear-Variable -Name GivenName -ErrorAction SilentlyContinue
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $PrincipalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
        $GivenName = ([System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($PrincipalContext,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,[Environment]::UserName)).GivenName
        $PrincipalContext.Dispose()
    }
    catch [System.Exception] {
        Write-Log -Level Warn -Message "$_."
    }

    if ($GivenName) {
        Write-Log -Message "Given name retrieved from Active Directory"
        $GivenName
    }
    
    elseif (-NOT($GivenName)) {
        Write-Log -Message "Given name not found in AD or no local AD available. Continuing looking for given name elsewhere"
        if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
            Write-Log -Message "Looking for given name in WMI with CCM client"
            $LoggedOnSID = Get-WmiObject -Namespace ROOT\CCM -Class CCM_UserLogonEvents -Filter "LogoffTime=null" | Select -ExpandProperty UserSID
            if ($LoggedOnSID.GetType().IsArray) {
                Write-Log -Message "Multiple SID's found. Skipping"
                $GivenName = ""
                $GivenName
            }
            else {
	            $RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData"
	            $DisplayName = (Get-ChildItem -Path $RegKey | Where-Object {$_.GetValue("LoggedOnUserSID") -eq $LoggedOnSID} | Select-Object -First 1).GetValue("LoggedOnDisplayName")
		        if ($DisplayName) {
                    Write-Log -Message "Given name found in WMI with the CCM client"
			        $GivenName = $DisplayName.Split()[0].Trim()
                    $GivenName
		        }
		        else {
			        $GivenName = ""
                    $GivenName
		        }
            }
        }
    }

    elseif (-NOT($GivenName)) {
        # More options for given name here

    }

    else {
        Write-Log -Message "No given name found. Using nothing as placeholder"
        $GivenName = ""
        $GivenName
    }
}

# Create Get-WindowsVersion function
# This is used to determine if the script is running on Windows 10 or not
function Get-WindowsVersion {
    $OS = Get-WmiObject Win32_OperatingSystem
    if (($OS.Version -like "10.0.*") -AND ($OS.ProductType -eq 1)) {
        Write-Log -Message "Running supported version of Windows. Windows 10 and workstation OS detected"
        return $true
    }
    elseif ($OS.Version -notlike "10.0.*") {
        Write-Log -Message "Not running supported version of Windows"
        return $false
    }
    else {
        Write-Log -Message "Not running supported version of Windows"
        return $false
    }
}

# Create Windows Push Notification function.
# This is testing if toast notifications generally are disabled within Windows 10
function Test-WindowsPushNotificationsEnabled {
    $ToastEnabledKey = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -ErrorAction Ignore).ToastEnabled
    if ($ToastEnabledKey -eq "1") {
        Write-Log -Message "Toast notifications are enabled in Windows"
        return $true
    }
    elseif ($ToastEnabledKey -eq "0") {
        Write-Log -Message "Toast notifications are not enabled in Windows. The script will run, but toasts might not be displayed"
        return $false
    }
    else {
        Write-Log -Message "The registry key for determining if toast notifications are enabled does not exist. The script will run, but toasts might not be displayed"
        return $false
    }
}


######### GENERAL VARIABLES #########

# Getting executing directory
$global:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Setting image variables
$LogoImage = "file:///c:\Toast\badgeimage.jpg"
$HeroImage = "file:///c:\Toast\heroimage.jpg"
$RunningOS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object BuildNumber

# Test if the script is being run on a supported version of Windows. Windows 10 AND workstation OS is required
$SupportedWindowsVersion = Get-WindowsVersion
if ($SupportedWindowsVersion -eq $False) {
    Write-Log -Message "Aborting script" -Level Warn
    Exit 1
}

# Testing for blockers of toast notifications in Windows
$WindowsPushNotificationsEnabled = Test-WindowsPushNotificationsEnabled

# If no config file is set as parameter, use the default. 
# Default is executing directory. In this case, the custom-message.xml must exist in same directory as the New-CoronaToast.ps1 file
if (-NOT($Config)) {
    Write-Log -Message "No config file set as parameter. Using local config file"
    $Config = Join-Path ($global:ScriptPath) "custom-message.xml"
}

# Load custom-message.xml
if (Test-Path $Config) {
    try { 
        $Xml = [xml](Get-Content -Path $Config -Encoding UTF8)
        Write-Log -Message "Successfully loaded $Config" 
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Message "Error, could not read $Config"
        Write-Log -Message "Error message: $ErrorMessage"
        Exit 1
    }
}
else {
    Write-Log -Message "Error, could not find or access $Config"
    Exit 1
}

# Load xml content into variables
try {
    Write-Log -Message "Loading xml content from $Config into variables"

    # Load Toast Notification features 
    $ToastEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -like 'Toast'} | Select-Object -ExpandProperty 'Enabled'

    # Load Toast Notification options   
    $SCAppName = $Xml.Configuration.Option | Where-Object {$_.Name -like 'UseSoftwareCenterApp'} | Select-Object -ExpandProperty 'Name'
    $SCAppStatus = $Xml.Configuration.Option | Where-Object {$_.Name -like 'UseSoftwareCenterApp'} | Select-Object -ExpandProperty 'Enabled'
    $PSAppName = $Xml.Configuration.Option | Where-Object {$_.Name -like 'UsePowershellApp'} | Select-Object -ExpandProperty 'Name'
    $PSAppStatus = $Xml.Configuration.Option | Where-Object {$_.Name -like 'UsePowershellApp'} | Select-Object -ExpandProperty 'Enabled'
    $CustomAudio = $Xml.Configuration.Option | Where-Object {$_.Name -like 'CustomAudio'} | Select-Object -ExpandProperty 'Enabled'
    $CustomAudioTextToSpeech = $Xml.Configuration.Option | Where-Object {$_.Name -like 'CustomAudio'} | Select-Object -ExpandProperty 'TextToSpeech'
    $Scenario = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Scenario'} | Select-Object -ExpandProperty 'Type'
    $Action = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Action'} | Select-Object -ExpandProperty 'Value'

    # Load Toast Notification buttons
    $ActionButtonEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'ActionButton'} | Select-Object -ExpandProperty 'Enabled'
    $ActionButtonContent = $Xml.Configuration.Option | Where-Object {$_.Name -like 'ActionButton'} | Select-Object -ExpandProperty 'Value'
    $DismissButtonEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'DismissButton'} | Select-Object -ExpandProperty 'Enabled'
    $DismissButtonContent = $Xml.Configuration.Option | Where-Object {$_.Name -like 'DismissButton'} | Select-Object -ExpandProperty 'Value'
    $SnoozeButtonEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'SnoozeButton'} | Select-Object -ExpandProperty 'Enabled'
    $SnoozeButtonContent = $Xml.Configuration.Option | Where-Object {$_.Name -like 'SnoozeButton'} | Select-Object -ExpandProperty 'Value'

    # Load Toast Notification text
    $GreetGivenName = $Xml.Configuration.Text| Where-Object {$_.option -like 'GreetGivenName'} | Select-Object -ExpandProperty 'Enabled'
    $AttributionText = $Xml.Configuration.Text| Where-Object {$_.Name -like 'AttributionText'} | Select-Object -ExpandProperty '#text'
    $HeaderText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'HeaderText'} | Select-Object -ExpandProperty '#text'
    $TitleText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'TitleText'} | Select-Object -ExpandProperty '#text'
    $BodyText1 = $Xml.Configuration.Text | Where-Object {$_.Name -like 'BodyText1'} | Select-Object -ExpandProperty '#text'
    $BodyText2 = $Xml.Configuration.Text | Where-Object {$_.Name -like 'BodyText2'} | Select-Object -ExpandProperty '#text'

    # New text options
    $SnoozeText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'SnoozeText'} | Select-Object -ExpandProperty '#text'
    $GreetMorningText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'GreetMorningText'} | Select-Object -ExpandProperty '#text'
	$GreetAfternoonText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'GreetAfternoonText'} | Select-Object -ExpandProperty '#text'
	$GreetEveningText = $Xml.Configuration.Text | Where-Object {$_.Name -like 'GreetEveningText'} | Select-Object -ExpandProperty '#text'

    Write-Log -Message "Successfully loaded xml content from $Config"     
}

catch {
    Write-Log -Message "Xml content from $Config was not loaded properly"
    Exit 1
}

# Check if toast is enabled in custom-message.xml
if ($ToastEnabled -ne "True") {
    Write-Log -Message "Toast notification is not enabled. Please check $Config file"
    Exit 1
}

# Checking for conflicts in config. Some combinations makes no sense, thus trying to prevent those from happening
if (($SCAppStatus -eq "True") -AND (-NOT(Get-Service -Name ccmexec))) {
    Write-Log -Level Warn -Message "Error. Using Software Center app for the notification requires the ConfigMgr client installed"
    Write-Log -Level Warn -Message "Error. Please install the ConfigMgr cient or use Powershell as app doing the notification"
    Exit 1
}
if (($SCAppStatus -eq "True") -AND ($PSAppStatus -eq "True")) {
    Write-Log -Level Warn -Message "Error. Conflicting selection in the $Config file" 
    Write-Log -Level Warn -Message "Error. You can't have both SoftwareCenter app set to True AND PowershellApp set to True at the same time"
    Exit 1
}
if (($SCAppStatus -ne "True") -AND ($PSAppStatus -ne "True")) {
    Write-Log -Level Warn -Message "Error. Conflicting selection in the $Config file" 
    Write-Log -Level Warn -Message "Error. You need to enable at least 1 app in the config doing the notification. ie. Software Center or Powershell"
    Exit 1
}



# Check for required entries in registry for when using Software Center as application for the toast
if ($SCAppStatus -eq "True") {

    # Path to the notification app doing the actual toast
    $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    $App = "Microsoft.SoftwareCenter.DesktopToasts"

    # Creating registry entries if they don't exists
    if (-NOT(Test-Path -Path "$RegPath\$App")) {
        New-Item -Path "$RegPath\$App" -Force
        New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD" -Force
        New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force
    }

    # Make sure the app used with the action center is enabled
    if ((Get-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne "1") {
        New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force
    }
}

# Check for required entries in registry for when using Powershell as application for the toast
if ($PSAppStatus -eq "True") {

    # Register the AppID in the registry for use with the Action Center, if required
    $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    $App =  "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
    
    # Creating registry entries if they don't exists
    if (-NOT(Test-Path -Path "$RegPath\$App")) {
        New-Item -Path "$RegPath\$App" -Force
        New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD"
    }
    
    # Make sure the app used with the action center is enabled
    if ((Get-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -ErrorAction SilentlyContinue).ShowInActionCenter -ne "1") {
        New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD" -Force
    }
}

# Checking if running toast with personal greeting with given name
if ($GreetGivenName -eq "True") {
    Write-Log -Message "Greeting with given name selected. Replacing HeaderText"
    $Hour = (Get-Date).TimeOfDay.Hours
    if ($Hour –ge 0 –AND $Hour –lt 12) {
        $Greeting = $GreetMorningText
    }
    elseif ($Hour –ge 12 –AND $Hour –lt 16) {
        $Greeting = $GreetAfternoonText
    }
    else {
        $Greeting = $GreetEveningText
    }
    
    $GivenName = Get-GivenName
    $HeaderText = "$Greeting $GivenName"
}


# Create the default toast notification XML with action button and dismiss button
if (($ActionButtonEnabled -eq "True") -AND ($DismissButtonEnabled -eq "True")) {
    Write-Log -Message "Creating the xml for displaying both action button and dismiss button"
[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
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
        <action activationType="protocol" arguments="$Action" content="$ActionButtonContent" />
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
    </actions>
</toast>
"@
}

# NO action button and NO dismiss button
if (($ActionButtonEnabled -ne "True") -AND ($DismissButtonEnabled -ne "True")) {
    Write-Log -Message "Creating the xml for no action button and no dismiss button"
[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
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
    </actions>
</toast>
"@
}

# Action button and NO dismiss button
if (($ActionButtonEnabled -eq "True") -AND ($DismissButtonEnabled -ne "True")) {
    Write-Log -Message "Creating the xml for no dismiss button"
[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
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
        <action activationType="protocol" arguments="$Action" content="$ActionButtonContent" />
    </actions>
</toast>
"@
}

# Dismiss button and NO action button
if (($ActionButtonEnabled -ne "True") -AND ($DismissButtonEnabled -eq "True")) {
    Write-Log -Message "Creating the xml for no action button"
[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
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
}

# Snooze button - this option will always enable both action button and dismiss button regardless of config settings
if ($SnoozeButtonEnabled -eq "True") {
    Write-Log -Message "Creating the xml for snooze button"
[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
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
        <input id="snoozeTime" type="selection" title="$SnoozeText" defaultInput="15">
            <selection id="15" content="15 $MinutesText"/>
            <selection id="30" content="30 $MinutesText"/>
            <selection id="60" content="1 $HourText"/>
            <selection id="240" content="4 $HoursText"/>
            <selection id="480" content="8 $HoursText"/>
        </input>
        <action activationType="protocol" arguments="$Action" content="$ActionButtonContent" />
        <action activationType="system" arguments="snooze" hint-inputId="snoozeTime" content="$SnoozeButtonContent"/>
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
    </actions>
</toast>
"@
}

# Toast run instruction
    Write-Log -Message "Displaying default toast notification"
    # Load required objects
    $Load = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    $Load = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

    # Load the notification into the required format
    $ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
    $ToastXml.LoadXml($Toast.OuterXml)
        
    # Display the toast notification
    try {
        Write-Log -Message "Displaying the toast notification"
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
    }
    catch { 
        Write-Log -Message "Something went wrong when displaying the toast notification" -Level Warn
        Write-Log -Message "Make sure the script is running as the logged on user" -Level Warn  
    }
    
    #if ($CustomAudio -eq "True") {
        
     #   Invoke-Command -ScriptBlock {Add-Type -AssemblyName System.Speech
      #  $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
       # $speak.Speak("$CustomAudioTextToSpeech")
        #$speak.Dispose()
        #}    
    #}
    # Stopping script. No need to accidently run further toasts
    break

