<# 
.SYNOPSIS
   Simple Toast Notification Script. 

.DESCRIPTION
   Simple Toast Notification Script that uses base64 to encode the heroimage and badgeimage.

.EXAMPLE
   PS C:\> .\Simple-Toast-Note.ps1
   Save the file to your hard drive with a .PS1 extention and run the file from an elavated PowerShell prompt.

.NOTES
   

.FUNCTIONALITY
   PowerShell v1+

#>

Param
(
    [Parameter(Mandatory = $False)]
    [String]$ToastGUID
)

#region ToastCustomisation

#Create Toast Variables
$AlertTime = (Get-Date -Format 'dd/MM @ hh:mm tt')

# $CustomHello = "This is a Test of Notifications"
$ToastTitle = "People Survey 2023"
$Signature = "Sent by University of Surrey: $AlertTime"
$EventTitle = "People Survey 2023 Make Your Voice Count."
$EventText = "Your personal link from People Insight, inviting you to complete the survey will be in your inbox."
$EventText2 = "The survey runs between Monday 11th September and Friday 6th October It only takes 15 minutes and will help shape the future of Surrey."
$EventText3 = "If we can achieve a 50% completion rate in week one, we will donate an additional 100 trees!!."
$ButtonTitle = "Take the Survey Now"
$ButtonAction = "https://it.surrey.ac.uk/contact-us"



#ToastDuration: Short = 7s, Long = 25s
$ToastDuration = "long"

#Images
# Picture Base64
# Create the picture object from a base64 code - HeroImage.

$Picture_Base64 = "/9j/4AAQSkZJRgABAQEASABIAAD/4QBmRXhpZgAATU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAAExAAIAAAAQAAAATgAAAAAAAABIAAAAAQAAAEgAAAABcGFpbnQubmV0IDUuMC41AP/bAEMAAgEBAQEBAgEBAQICAgICBAMCAgICBQQEAwQGBQYGBgUGBgYHCQgGBwkHBgYICwgJCgoKCgoGCAsMCwoMCQoKCv/bAEMBAgICAgICBQMDBQoHBgcKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCv/AABEIALQBbAMBEgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/AP38ooAKKACigAooAK87+L37S/w7+EUjaXfTyahqm3P9m2ZBZPTex4T6cn2r53OOLOGshfLj8VCnL+Vu8v8AwFXl+BLlFbnolfLOoft+eNJLktpXgTTIYd3yrcTSSNj6gqP0r46p4y8A05WWIk/NU5/qkT7SJ9TV89+Bf29ND1C6Sy+IPhN9PVmx9tsZDKi+5QjcB9CT7V6OB8VOA8wkoQxii/76lD8ZJR/EftIn0JVTQ9d0fxLpUOuaBqUN5Z3CbobiB9ysP8/iK+8oYihiqSq0ZKUXs000/RrRlluitgCigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigDzv8AaX+L8nwh+Hcl9pbr/amoSfZ9N3fwNjLSY/2R+pWvHP2+9RuZfG2h6WzN5MOmPIq9tzSYJ/JRX4V4yccZnw/TpZZl8nCdWLlKa3Ub2Si+jbvdrVLbcyqScdEeDXl5d6hdyX9/cyTTTSF5ppGLM7E5JJPU1HX8pTqTqTc5ttvVt6t+pgFFSAUUAetfsnfGu/8Ah144g8K6peM2i6xOsUsbt8sEzcLKPTnAb1Bz2FeTxySQyLLExVlbKsOx9a+u4R40znhDHxrYWbdO/v02/dkuunR22ktV6XRUZOJ+kVUPCt7NqXhfTdRuP9ZcWEMj/VkBP86/u7C4iGMwtOvDacVJejV1+Z1F+iugAooAKKACigAooAKKACigAozzigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKADJ9KKAAE/3aKADn0ooAKKACigAooAKKACigAooAKKACigAoZgo3McD1NAHz1+3p4Fur7RdJ+INlCzLYu1re7R91HIKN9NwI+rCvddZsPDni/SLrw3qwt7u1u4WiuLfzAdyn6dP6GvzbxE4Bw/HGDg6c1DEU78kns094ytrbs1dp9HdozlHmPzrr1j41/soeOPhxfzan4XsZ9X0UsWjmt03TQL/dkUc8f3gMH26V/KGdcC8V8P1GsZhZ8q+1Fc0H/wBvRul6Oz8jFxlE8npXR43MciFWU4ZWGCK+Taa0ZIlbHg7wD4x8f6iuleD/AA9c30xbDeTH8qe7MflUfUiuzB5fmGY1PZ4SlKpLtGLk/uSYB8PvB+oePvGmm+ENMiZpL66WNiv8CZyzH2C5P4VrftHftf8AwC/4JH+BxqXjoxeLPitrtiW0nwrp9wF+zxH+OWTB8mLcOXxucrhFIBI/a+CPBXOsyxUMTnMfZUU0+S/vz8ml8KfW75ulluvPzDOMryePNjayh5byfpFXb+4+8rO1hsbSKyt12xwxqkY9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R4L0O30zSNJs47TTdPs4wkVvCihURR2AAFaVc59/CEKcVGCsloktEgooKCigAooAKKACigAooAKKACigAooAKKACigAooAKKADGaKAE2kdDS0AFFABRQAhXJzS0AFFABRQAUUAFFABRQAU1lyaAHUUABBPeigAooAKCcdaACigAooAKKACigAooAKKACigAooAKKACigCO6do7aR0OGWMkflRef8ec3/AFzb+VAH5g/8Ee/2/f2tv2mP20/FXwr+N3xdm1zQdO0C/uLOwk021hEckd1EiNuiiVjhWI5JHNeOf8EBf+Uivjf/ALFfU/8A0tgrhw8pSqWbOqtGKgrI/aWiu45QooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAooAKKACigAPSkY4U8UAIcgEj+dcH4/+Lz+H/EC+BtDtVbU5brTYo5rjmJftUswbIBzlIraVu2TtGea8PMeIMqyupGlWqe9J2SXd/gvmzelh61WLcVsUfjd8YH+Gur6LI+peVYyG7e4WGMSSXlwkI8ixTrh5TJuGOT5foSa8P0/4haR4JW/+KOvzjxFqC69qt34J8O2tuz+bCt1L5+qTYPynYGjWRvlSOIbQea/Kc444qYytNzq/VaUG4tuTbaXWMIPmb7aOJ7VDLeSKSXPJ9Oz829F+DPpvwN/bOhfDnSf+E21NpNQttJhOrXEzdZhGPMJP1zXzpcfH74u/tLXOh+DPAT+G9Bh1iaZrhIdWkvry2tlgdXe5jRUWNCWChXO4uyYHGa9an4kZXPAww2SqpiqzSUfccbv+aXPy6d3ovMyllGIjWcsQ1CPXVP5K1z3D4R/GEfEy8mSWGO2E9rHf6XZKrtMti5KxTXDY2o8uCyxgkhRkk84sfBP4NaF8FfCaeHNMvri/updr6hql1/rbp1UIuf7qKqqqrkhVGOeSfr+GY8USpurm1ot/YupNP1jaKXlaT/vM4MW8GpctDXz2/B6/PT0O0or604goPSgAoHSgAooAKKACigAooAKKAI7z/jzm/65t/Ki8/485v8Arm38qAPxe/4IC/8AKRXxv/2K+p/+lsFH/BAX/lIr43/7FfU//S2CuDDfxWdmI/ho/YD4zXV1Y/B/xZe2VzJDND4avnhmicqyMLdyGBHI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"
$HeroImage = "$env:TEMP\HeroPicture.png"
[byte[]]$Bytes = [convert]::FromBase64String($Picture_Base64)
[System.IO.File]::WriteAllBytes($HeroImage,$Bytes)
# Picture Base64 end

# Picture Base64
# Create the picture object from a base64 code - BadgeImage.

$Picture1_Base64 = "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"
$BadgeImage = "$env:TEMP\badgePicture.png"
[byte[]]$Bytes = [convert]::FromBase64String($Picture1_Base64)
[System.IO.File]::WriteAllBytes($BadgeImage,$Bytes)
# Picture Base64 end

#endregion ToastCustomisation

#region ToastRunningValues

#Set Unique GUID for the Toast
If (!($ToastGUID))
{
	$ToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
}

#Current Directory
$ScriptPath = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path $ScriptPath

#Set Toast Path to UserProfile Temp Directory
$ToastPath = (Join-Path $ENV:Windir "Temp\$($ToastGuid)")

$ToastPSFile = $MyInvocation.MyCommand.Name

#endregion ToastRunningValues

#region ScriptFunctions
# Toast function
function Display-ToastNotification
{
	
	#Set COM App ID > To bring a URL on button press to focus use a browser for the appid e.g. MSEdge
	#$LauncherID = "Microsoft.SoftwareCenter.DesktopToasts"
	#$Launcherid = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
	#$LauncherID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
	$Launcherid = "MSEdge"
	
	#Dont Create a Scheduled Task if the script is running in the context of the logged on user, only if SYSTEM fired the script i.e. Deployment from Intune/ConfigMgr
	If (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM")
	{
		
		#Prepare to stage Toast Notification Content in %TEMP% Folder
		Try
		{
			
			#Create TEMP folder to stage Toast Notification Content in %TEMP% Folder
			New-Item $ToastPath -ItemType Directory -Force -ErrorAction Continue | Out-Null
			$ToastFiles = Get-ChildItem $CurrentDir -Recurse
			
			#Copy Toast Files to Toat TEMP folder
			ForEach ($ToastFile in $ToastFiles)
			{
				Copy-Item (Join-Path $CurrentDir $ToastFile) -Destination $ToastPath -ErrorAction Continue
			}
		}
		Catch
		{
			Write-Warning $_.Exception.Message
		}
		
		#Set new Toast script to run from TEMP path
		$New_ToastPath = Join-Path -Path $ToastPath -ChildPath $ToastPSFile
		
		#Created Scheduled Task to run as Logged on User
		$Task_TimeToRun = (Get-Date).AddSeconds(30).ToString('s')
		$Task_Expiry = (Get-Date).AddSeconds(120).ToString('s')
		$Task_Action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File ""$New_ToastPath"" -ToastGUID ""$ToastGUID"""
		$Task_Trigger = New-ScheduledTaskTrigger -Once -At $Task_TimeToRun
		$Task_Trigger.EndBoundary = $Task_Expiry
		$Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
		$Task_Settings = New-ScheduledTaskSettingsSet -Compatibility V1 -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600) -AllowStartIfOnBatteries
		$New_Task = New-ScheduledTask -Description "Toast_Notification_$($ToastGuid) Task for user notification. Title: $($EventTitle) :: Event:$($EventText) :: Source Path: $($ToastPath) " -Action $Task_Action -Principal $Task_Principal -Trigger $Task_Trigger -Settings $Task_Settings
		Register-ScheduledTask -TaskName "Toast_Notification_$($ToastGuid)" -InputObject $New_Task
	}
	
	#Run the toast of the script is running in the context of the Logged On User
	If (!(([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM"))
	{
		
		$Log = (Join-Path $ENV:Windir "Temp\$($ToastGuid).log")
		Start-Transcript $Log
		
		#Get logged on user DisplayName
		#Try to get the DisplayName for Domain User
		$ErrorActionPreference = "Continue"
		
		Try
		{
			Write-Output "Trying Identity LogonUI Registry Key for Domain User info..."
			Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnDisplayName" -ErrorAction Stop | out-null
			$User = Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnDisplayName" | Select-Object -ExpandProperty LastLoggedOnDisplayName -ErrorAction Stop | out-null
			
			If ($Null -eq $User)
			{
				$Firstname = $Null
			}
			else
			{
				$DisplayName = $User.Split(" ")
				$Firstname = $DisplayName[1]
			}
		}
		Catch [System.Management.Automation.PSArgumentException] {
			"Registry Key Property missing"
			Write-Warning "Registry Key for LastLoggedOnDisplayName could not be found."
			$Firstname = $Null
		}
		Catch [System.Management.Automation.ItemNotFoundException] {
			"Registry Key itself is missing"
			Write-Warning "Registry value for LastLoggedOnDisplayName could not be found."
			$Firstname = $Null
		}
		
		#Try to get the DisplayName for Azure AD User
		If ($Null -eq $Firstname)
		{
			Write-Output "Trying Identity Store Cache for Azure AD User info..."
			Try
			{
				$UserSID = (whoami /user /fo csv | ConvertFrom-Csv).Sid
				$LogonCacheSID = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache -Recurse -Depth 2 | Where-Object { $_.Name -match $UserSID }).Name
				If ($LogonCacheSID)
				{
					$LogonCacheSID = $LogonCacheSID.Replace("HKEY_LOCAL_MACHINE", "HKLM:")
					$User = Get-ItemProperty -Path $LogonCacheSID | Select-Object -ExpandProperty DisplayName -ErrorAction Stop
					$DisplayName = $User.Split(" ")
					$Firstname = $DisplayName[1]
				}
				else
				{
					Write-Warning "Could not get DisplayName property from Identity Store Cache for Azure AD User"
					$Firstname = $Null
				}
			}
			Catch [System.Management.Automation.PSArgumentException] {
				Write-Warning "Could not get DisplayName property from Identity Store Cache for Azure AD User"
				Write-Output "Resorting to whoami info for Toast DisplayName..."
				$Firstname = $Null
			}
			Catch [System.Management.Automation.ItemNotFoundException] {
				Write-Warning "Could not get SID from Identity Store Cache for Azure AD User"
				Write-Output "Resorting to whoami info for Toast DisplayName..."
				$Firstname = $Null
			}
			Catch
			{
				Write-Warning "Could not get SID from Identity Store Cache for Azure AD User"
				Write-Output "Resorting to whoami info for Toast DisplayName..."
				$Firstname = $Null
			}
		}
		
		#If DisplayName could not be obtained, leave it blank.
		If ($Null -eq $Firstname)
		{
			Write-Output "DisplayName could not be obtained, it will be blank in the Toast"
		}

		#Load Assemblies
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
		
		#Build XML ToastTemplate 
		[xml]$ToastTemplate = @"
		<toast duration="$ToastDuration" scenario="reminder">
    <visual>
        <binding template="ToastGeneric">
            <text>$ToastTitle</text>
            <text placement="attribution">$Signature</text>
            <image placement="hero" src="$HeroImage"/>
            <image placement="appLogoOverride" hint-crop="circle" src="$BadgeImage"/>
            <group>
                <subgroup>
                    <text hint-style="title" hint-wrap="true" >$EventTitle</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                    <text hint-style="body" hint-wrap="true" >$EventText</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                    <text hint-style="body" hint-wrap="true" >$EventText2</text>
                </subgroup>
            </group>
			<group>
			<subgroup>
				<text hint-style="body" hint-wrap="true" >$EventText3</text>
			</subgroup>
		</group>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:notification.default"/>
</toast>
"@
		
		#Build XML ActionTemplate 
		[xml]$ActionTemplate = @"
<toast>
    <actions>
        <action arguments="$ButtonAction" content="$ButtonTitle" activationType="protocol" />
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
    </actions>
</toast>
"@
		
		#Define default actions to be added $ToastTemplate
		$Action_Node = $ActionTemplate.toast.actions
		
		#Append actions to $ToastTemplate
		[void]$ToastTemplate.toast.AppendChild($ToastTemplate.ImportNode($Action_Node, $true))
		
		#Prepare XML
		$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
		$ToastXml.LoadXml($ToastTemplate.OuterXml)
		
		#Prepare and Create Toast
		$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($LauncherID).Show($ToastMessage)
		
		Stop-Transcript
	}
}
#endregion RegionName

#region ScriptRunningCode

# Display notification for drive failure if present in the registy
$DriveHealthIssue = [boolean](Get-ChildItem -Path $RegistryBase -Recurse | Get-ItemProperty | Where-Object { $_.Output -notmatch "No action required" })
if ($DriveHealthIssue -eq $true)
{
	Display-ToastNotification
}

#endregion ScriptRunningCode

## Create Detection Method that Toast has run. 
$logfilespath = "C:\logfiles"
If(!(test-path $logfilespath))
{
      New-Item -ItemType Directory -Force -Path $logfilespath
}

New-Item -ItemType "file" -Path "c:\logfiles\People_Survey_2023_01.txt"