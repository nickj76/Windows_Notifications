# Windows-Notifications - using Simple Toast Note

This is a PowerShell Script to show custom toast notifications in windows. Everything is contained within the script for simplicity.

Template file to copy: Simple-Toast-Note-v2.4.ps1 (this is the current live version)

To change the message displayed open the script in your preferred editor and scroll to line 30 or #create toast variables and change as needed, this eliminated the need to point to an xml file.

$ToastTitle = "Important Information: Please review the details below before contacting the Service Desk."

$Signature = "Sent on behalf of the IT Service Desk."

$EventTitle = "Major IT Issues - All Systems Currently Offline."

$EventText = "We are currently experiencing problems with all our systems. We are drinking coffee with our feet up and will provide an update shortly. Thank you for your patience."

$ButtonTitle = "IT Service Desk"

$ButtonAction = "https://it.surrey.ac.uk/contact-us"

Toast display duration can be changed on line 38

#ToastDuration: Short = 7s, Long = 25s

$ToastDuration = "long"

Change AppID on line 86

#Set COM App ID > To bring a URL on button press to focus use a browser for the appid e.g. MSEdge

#$LauncherID = "Microsoft.SoftwareCenter.DesktopToasts"

#$Launcherid = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"

#$LauncherID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

$Launcherid = "MSEdge"

Toast Hero Image

The Toast Hero Image should be 364 x 180 (Width = 364 pixels, Height = 180 pixels)

Once you have decided on your hero image you need to convert image to Base64, I use https://base64.guru/converter/encode/image now for the really cool part you can now use this base64 code in the script to create the picture object, meaning you don't need to point to image files or download image files.


