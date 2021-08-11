This is a PowerShell Script to show custom toast notifications in windows. Everything is contained within the script for simplicity.

Variables.

To change the message displayed open the script in your preferred editor and scroll to line 28 or #create toast variables and change as needed, this eliminated the need to point to an xml file.

#Create Toast Variables
$HeaderText = "Warning......Device Health Issue Detected."
$CustomHello = "Missing or Disabled Device Driver."
$ToastTitle = "Please note that a device driver is missing or disabled on your device. Please contact the IT service desk for assistance in fixing this."
$Signature = "IT Services"
$ButtonTitle = "IT Service Desk"
$ButtonAction = "https://www.example.com/contact-us"

Toast display duration can be changed on line 37

#ToastDuration: Short = 7s, Long = 25s
$ToastDuration = "long"

Toast Hero Image;

The Toast Hero Image should be 364 x 180 (Width = 364 pixels, Height = 180 pixels

Once you have decided on your hero image you need to convert image to Base64, I use https://base64.guru/converter/encode/image now for the really cool part you can now use this base64 code in the script to create the picture object, meaning you don't need to point to image files or download image files.