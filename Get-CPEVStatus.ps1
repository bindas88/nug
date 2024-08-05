Function Get-CPEVStatus {
    
    # Check if running with administrative privileges
    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not $isAdmin) {
        Write-Host "This script requires administrative privileges. Please elevate using UAC."
        exit
    }

    $script:UsersAndTheirHomes = Get-CimInstance win32_userprofile | ForEach-Object {try {$out = new-object psobject;$out | Add-Member noteproperty Name (New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value;$out | Add-Member noteproperty LocalPath $_.LocalPath;$out} catch {}};
    $script:CurrentUserHome = ($script:UsersAndTheirHomes | Where {$_.Name -eq ((Get-CimInstance -className Win32_ComputerSystem).UserName)}).LocalPath
    $script:LocalApplicationData = (Join-Path $script:CurrentUserHome 'AppData\Local')

    Add-Type -AssemblyName System.Security

    if (-not (Get-Module -Name getsql -ListAvailable)) {
        Write-Host "Installing Required module: GetSQL..."
        Install-Module -Name getsql -Force -AcceptLicense -Scope CurrentUser -AllowClobber
    }

    if (-not (Get-Module -Name "*BouncyCastle*")) {
        Write-Host "Streaming in Temp module: BouncyCastle..."
        Import-Module ([System.Reflection.Assembly]::Load((Invoke-WebRequest -UseBasicParsing -Uri "https://downloads.bouncycastle.org/csharp/2.4.0/netstandard2.0/BouncyCastle.Cryptography.dll").content));
    }

    if (!(Get-Command -Name "PSRunAsCurrentUser" -CommandType Function -ErrorAction SilentlyContinue)){
        iex ((New-Object System.Net.WebClient).DownloadString("https://rawcdn.githack.com/AlecMcCutcheon/PSRunAsCurrentUser/b419b135641597982a2a4fa38e27502cde172584/PSRunAsCurrentUser.ps1"));
    }

    Import-Module -Name getsql

    function OBCPSRunAsCurrentUser {
      param(
        [scriptblock]$ScriptBlock,
        [switch]$ForceFallback
      )

      $UsersAndTheirHomes = Get-WmiObject win32_userprofile | ForEach-Object { try { $out = New-Object psobject; $out | Add-Member noteproperty Name (New-Object System.Security.Principal.SecurityIdentifier ($_.SID)).Translate([System.Security.Principal.NTAccount]).Value; $out | Add-Member noteproperty LocalPath $_.LocalPath; $out } catch {} };
      $CurrentUserHome = ($UsersAndTheirHomes | Where-Object { $_.Name -eq ((Get-WmiObject -Class Win32_ComputerSystem).UserName) }).LocalPath;

      if ($ForceFallback) {
        function RunAsVBS { return $false }
      } else {
        function RunAsVBS {
          $EncodedCommandTest = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(([scriptblock]::Create("((New-Item -Path '$CurrentUserHome\VBSTest.log' -Value 'Test').Attributes='Hidden')"))));
          ((New-Item -Path "$CurrentUserHome\VBSTest.vbs" -Value ("command = " + '"Powershell.exe -NonInteractive -WindowStyle Hidden -NoLogo -NoProfile -EncodedCommand ' + "$EncodedCommandTest" + '"' + "`n" + 'set shell = CreateObject("WScript.Shell")' + "`n" + "shell.Run command,0")).Attributes = "Hidden") > $null;
          wscript.exe "$CurrentUserHome\VBSTest.vbs";
          Start-Sleep -Seconds 2;
          if (Test-Path "$CurrentUserHome\VBSTest.vbs") { Remove-Item "$CurrentUserHome\VBSTest.vbs" -Confirm:$false -Force; }
          if (Test-Path "$CurrentUserHome\VBSTest.log") { Remove-Item "$CurrentUserHome\VBSTest.log" -Confirm:$false -Force; return $true; } else { return $false; }
        }
      }

      $TranscriptStart = "((New-Item -Path '$CurrentUserHome\RunASCurrentUserTemp.log' -Value '').Attributes='Hidden');Start-Transcript '$CurrentUserHome\RunASCurrentUserTemp.log' -Append" + ' > $null';
      $TranscriptEnd = "Stop-Transcript; Set-Content '$CurrentUserHome\RunASCurrentUserOutput.log' -Value (Get-Content '$CurrentUserHome\RunASCurrentUserTemp.log' -Force);";
      $Marker = (([guid]::NewGuid()).GUID);
      $ScriptBlock = [scriptblock]::Create($TranscriptStart + "`n" + "Write-Output '" + $Marker + "'" + "`n" + ($ScriptBlock).ToString() + "`n" + "Write-Output '" + $Marker + "'" + "`n" + $TranscriptEnd);
      $EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
      if (!(Test-Path "$CurrentUserHome\RunASCurrentUserOutput.log")) { ((New-Item -Path "$CurrentUserHome" -Name "RunASCurrentUserOutput.log" -Type "file").Attributes = 'Hidden') > $null };
      if (!(Test-Path "$CurrentUserHome\RunASCurrentUserTemp.log")) { ((New-Item -Path "$CurrentUserHome" -Name "RunASCurrentUserTemp.log" -Type "file").Attributes = 'Hidden') > $null };
      Set-Content "$CurrentUserHome\RunASCurrentUserOutput.log" -Value "" -Force;
      Set-Content "$CurrentUserHome\RunASCurrentUserTemp.log" -Value "" -Force;
      Unregister-ScheduledTask -TaskName 'OBCRunASCurrentUser' -Confirm:$false -ErrorAction SilentlyContinue;
      $LastWriteTime = (Get-Item "$CurrentUserHome\RunASCurrentUserOutput.log" -Force).LastWriteTime;

      if (RunAsVBS) {
        ((New-Item -Path "$CurrentUserHome\RunASCurrentUser.vbs" -Value ("command = " + '"Powershell.exe -NonInteractive -WindowStyle Hidden -NoLogo -NoProfile -EncodedCommand ' + "$EncodedCommand" + '"' + "`n" + 'set shell = CreateObject("WScript.Shell")' + "`n" + "shell.Run command,0")).Attributes = 'Hidden') > $null;
        $PSPath = "C:\Windows\System32\wscript.exe";
        $Args = "$CurrentUserHome\RunASCurrentUser.vbs";
      } else {
        $PSPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        $Args = "-NonInteractive -WindowStyle Hidden -NoLogo -NoProfile -EncodedCommand $EncodedCommand";
      }

      $Action = New-ScheduledTaskAction -Execute $PSPath -Argument $Args;
      $Option = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun -DontStopOnIdleEnd -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 2 -StartWhenAvailable;
      $Option.ExecutionTimeLimit = "PT0S";
      $Trigger = New-JobTrigger -Once -at ((Get-Date) + (New-TimeSpan -Minutes 5)) -RandomDelay (New-TimeSpan -Minutes 1);
      Register-ScheduledTask -User ((Get-WmiObject -Class Win32_ComputerSystem).UserName) -TaskName "OBCRunASCurrentUser" -Action $Action -Trigger $Trigger -Settings $Option > $null;
      Start-ScheduledTask -TaskName 'OBCRunASCurrentUser';
      do { Start-Sleep -Seconds 1 } while (((Get-Item "$CurrentUserHome\RunASCurrentUserOutput.log" -Force).LastWriteTime -eq $LastWriteTime));
      Unregister-ScheduledTask -TaskName 'OBCRunASCurrentUser' -Confirm:$false;
      $RunAsCurrentUserOutput = (((Get-Content ((Get-Item "$CurrentUserHome\RunASCurrentUserOutput.log" -Force).FullName)) | Out-String) -split $Marker)[1];
      if (Test-Path "$CurrentUserHome\RunASCurrentUserOutput.log") { Remove-Item "$CurrentUserHome\RunASCurrentUserOutput.log" -Confirm:$false -Force; };
      if (Test-Path "$CurrentUserHome\RunASCurrentUserTemp.log") { Remove-Item "$CurrentUserHome\RunASCurrentUserTemp.log" -Confirm:$false -Force; };
      if (Test-Path "$CurrentUserHome\RunASCurrentUser.vbs") { Remove-Item "$CurrentUserHome\RunASCurrentUser.vbs" -Confirm:$false -Force; };
      return $RunAsCurrentUserOutput;
    }

    function ProtectedData($EncryptedKey) {
        
        if ($PSVersionTable.PSVersion.Major -ge 7 -or $psISE) {
            [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedKey,  $null, 'CurrentUser')
        }else{
            $EncryptedKey | Convertto-Json | Out-File -FilePath "$env:TEMP\KeyJSON.JSON"

            $Scriptblock = [ScriptBlock]{ 
            $Key = [byte[]](Get-content "$env:TEMP\KeyJSON.JSON" | Convertfrom-Json); 
            Add-Type -AssemblyName System.Security;
            [System.Security.Cryptography.ProtectedData]::Unprotect($Key,  $null, 'CurrentUser') | ConvertTo-Json
            }

            OBCPSRunAsCurrentUser -ScriptBlock $Scriptblock | ConvertFrom-Json
        }

    }

    function Get-ChromiumCredentials {
        [CmdletBinding()]
        param (
            $DbPath = (Join-Path $script:LocalApplicationData '\Google\Chrome\User Data\Default\Login Data'),
            $StatePath,
            $Table = "logins",
            $Property = @(
                @{n='username'; e='username_value'},
                @{n='password'; e={ConvertTo-SecureString -String (Unprotect $_.password_value) -AsPlainText -Force}},
                @{n='url'; e='signon_realm'}
            ),

            $KeyPath,

            $CsvPath = (Join-Path -Path "C:/" -ChildPath "Passwords.csv")
        )
        Write-Host "Retrieving chromium passwords under $DbPath..."
        try {
            $sqliteFile = Copy-Item -PassThru $DbPath -Destination $env:TEMP -ErrorAction Stop
        } catch {
            Write-Warning "Could not make a working copy of $DbPath"
            return
        }

        if (-not $PSBoundParameters.ContainsKey('StatePath')) {
            $StatePath = Join-Path (Split-Path (Split-Path $DbPath)) 'Local State'
        }
        if ($StatePath) {
            $localStateInfo = Get-Content -Raw $StatePath | ConvertFrom-Json
        }
        if ($localStateInfo) {
            $encryptedkey = [convert]::FromBase64String($localStateInfo.os_crypt.encrypted_key)
        }
        if ($encryptedkey -and [string]::new($encryptedkey[0..4]) -eq 'DPAPI') {
            $masterKey = ProtectedData($encryptedkey | Select-Object -Skip 5)
            if ($KeyPath) {
                [convert]::ToBase64String($masterkey) | Out-Default $KeyPath
            }
            $Script:GCMKey = $masterKey
        } else {
            Write-Warning 'Could not get key for new-style encryption. Will try with older Style'
        }

    function Decrypt-AesGcm {
        param (
            [byte[]]$key,
            [byte[]]$nonce,
            [byte[]]$ciphertext,
            [byte[]]$tag,
            [byte[]]$associatedData = $null
        )

        # Create a KeyParameter object with the provided key byte array
        $keyParameter = New-Object Org.BouncyCastle.Crypto.Parameters.KeyParameter($key, 0, $key.Length)

        $aesEngine = New-Object Org.BouncyCastle.Crypto.Engines.AesEngine
        $gcmBlockCipher = New-Object Org.BouncyCastle.Crypto.Modes.GcmBlockCipher($aesEngine)
    
        $parameters = New-Object Org.BouncyCastle.Crypto.Parameters.AeadParameters($keyParameter, 128, $nonce, $associatedData)

        $gcmBlockCipher.Init($false, $parameters)

        $combinedCiphertext = $ciphertext + $tag
        $plaintext = New-Object byte[] ($gcmBlockCipher.GetOutputSize($combinedCiphertext.Length))
        $len = $gcmBlockCipher.ProcessBytes($combinedCiphertext, 0, $combinedCiphertext.Length, $plaintext, 0)
        $gcmBlockCipher.DoFinal($plaintext, $len) | Out-Null

        return $plaintext
    }


    function Unprotect {
        param (
            [byte[]]$Encrypted
        )
        $Script:DecodeCount++
        try {
            if ($Script:GCMKey -and [string]::new($Encrypted[0..2]) -match "v1\d") {
                $nonce = $Encrypted[3..14]
                $ciphertext = $Encrypted[15..($Encrypted.Length-17)]
                $tag = $Encrypted[-16..-1]
                $output = Decrypt-AesGcm -key $Script:GCMKey -nonce $nonce -ciphertext $ciphertext -tag $tag
                return [System.Text.Encoding]::UTF8.GetString($output)
            } else {
                return [System.Text.Encoding]::UTF8.GetString((ProtectedData($Encrypted)))
            }
        } catch {
            Write-Error "Decryption failed: $_"
        }
    }

        $Script:DecodeCount = 0
        $savedRows = Get-SQL -Lite -Connection $sqliteFile -Table $Table -Quiet -Close
        $Output = $savedRows | Select-Object -Property $Property | where-object {$_.password -ne $null}
        if ($Output.password) {
            return [PSCustomObject]@{
                Status = $true
                CredCount = $Output.Count
            }
        } else {
            return [PSCustomObject]@{
                Status = $false
                CredCount = "N/A"
            }
        }
        try {
            Remove-Item $sqliteFile -ErrorAction Stop
        } catch {}
    }

    function Get-DefaultAndProfileFolders {
        param (
            [string]$rootPath = $script:LocalApplicationData
        )

        function FindDefaultAndProfileFolders {
            param (
                [string]$rootPath
            )

            $defaultFolders = Get-ChildItem -Path $rootPath -Directory -Filter "Default" -Recurse -Depth 3 |
                             Where-Object { $_.FullName -like "*\User Data\Default" } |
                             Select-Object -ExpandProperty FullName

            $profileFolders = Get-ChildItem -Path $rootPath -Directory -Filter "Profile*" -Recurse -Depth 3 |
                              Where-Object { $_.FullName -like "*\User Data\Profile*" } |
                              Select-Object -ExpandProperty FullName

            $defaultFolders + $profileFolders
        }

        $defaultAndProfileFolders = FindDefaultAndProfileFolders -rootPath $rootPath

        if ($defaultAndProfileFolders) {
            return $defaultAndProfileFolders
        }
    }

    function Get-BrowserAlias ($path) {
        $localAppDataPath = $script:LocalApplicationData
        $pathComponents = $path -split [regex]::Escape($localAppDataPath)
        $browserFolder = ($pathComponents[1] -split "\\User Data\\*")[0]
        if (-not $browserFolder) {
            $browserFolder = $pathComponents[1].Split("\User Data\")[0]
        }

        if ($browserFolder -and $browserFolder -ne "\") {
            $desiredPath = $browserFolder -replace '\\', '_'
            $desiredPath = $desiredPath -replace ' ', '_'
            $desiredPath.Trim('_')
        } else {
            $browserFolder = $pathComponents[1].Split("\User Data\")[0]
            $desiredPath = $browserFolder.Substring($browserFolder.LastIndexOf("\") + 1)
        }
        return $desiredPath
    }

    function Trim-PathToUserData {
        param (
            [string]$Path
        )

        $target = "\User Data"

        # Loop until the path ends with '\User Data' or is too short
        while ($Path -and -not $Path.EndsWith($target)) {
            $Path = [System.IO.Path]::GetDirectoryName($Path)
        }

        # Return the final path
        return $Path
    }

    function Get-ChromiumProfile {
        [CmdletBinding(DefaultParameterSetName='Name')]
        param(
            [Parameter(ParameterSetName='Name', Mandatory=$false, Position=0)]
            [string]
            $ProfileName,

            [Parameter(ParameterSetName='Id', Mandatory=$false, Position=0)]
            [string]
            $ProfileId,
            [string]
            $ChromiumFolder = (Join-Path $script:LocalApplicationData "\Google\Chrome\User Data\Local State")
        )

        # Get profile list from Chromes local state
        $state = Get-Content $ChromiumFolder -Raw

        # Convert JSON to object
        $jsonData = $state | ConvertFrom-Json

        $serProfiles = $jsonData.profile.info_cache
        $Count = 0
        $profiles = @()
        $ProfileCount = (($serProfiles | Get-Member -MemberType Properties).name.count)
        while ($Count -lt $ProfileCount) {
            if ($ProfileCount -eq 1) {
                $Id = (($serProfiles | Get-Member -MemberType Properties).Name)
            }else{
                $Id = (($serProfiles | Get-Member -MemberType Properties).Name)[$Count]
            }
            if ($Id) {
                $profile = New-Object -TypeName psobject -Property @{
                    'Id' = ($Id)
                    'Name' = ($serProfiles.$Id.shortcut_name)
                    'Email' = ($serProfiles.$Id.user_name)
                }
                $profiles += $profile
                $Count++
            }
        }

        if($PSBoundParameters['ProfileId']) {
            $profiles.Where{$_.Id -like "$ProfileId"}
        }
        elseif ($PSBoundParameters['ProfileName']) {
            $profiles.Where{$_.Name -like "$ProfileName"}
        }
        else {
            $profiles
        }
    }

    Write-Host "==================================================="
    Write-Host " Chromium Password Extraction Vulnerability Status"
    Write-Host "==================================================="
    Write-Host ""
    Write-Host "Locating all chromium-based browsers..."
    Write-Host ""
    $Folders = Get-DefaultAndProfileFolders
    $VulnerableFolders = @()

    Foreach ($Folder in $Folders) {
    $ChromiumCredentialStatus = (Get-ChromiumCredentials -DbPath "$Folder\Login Data")
        if ($ChromiumCredentialStatus.Status) {
            $VulnerableFolders += [PSCustomObject]@{
                Path = $Folder
                CredCount = $ChromiumCredentialStatus.CredCount
            }
        }
    }

    Write-Host ""

    if ($VulnerableFolders.Path.Count -gt 0) {

        Write-Host "Vulnerable Chromium Profiles"
        Write-Host "----------------------------"
        $ProfileObjects = @()
        $VulnerableFolders | ForEach-Object {
        $Path = $_.Path
        $CredCount = $_.CredCount
        $TrimmedPath = Trim-PathToUserData -Path $Path
        $UserDataFolder = "$TrimmedPath\Local State"
        $ChromiumProfile = Get-ChromiumProfile -ChromiumFolder $UserDataFolder | Where-Object {$Path -match $_.Id}
        $Email = $ChromiumProfile.Email
        if (!$Email) {$Email = "N/A"}

        $ProfileObject = [PSCustomObject]@{
            Profile_ID = $ChromiumProfile.Id
            Profile_Name = $ChromiumProfile.Name
            Profile_Email = $Email
            Profile_CredCount = $CredCount
            Profile_Path = $Path
        }
        
        $ProfileObjects += $ProfileObject

        }

        $ProfileObjects | Format-List
        Write-Host "----------------------------"
        Write-Host ""

        # CPEV (Chromium Password Extraction Vulnerability)
        Write-Warning "CPEV Status: $true"
    } else {
        Write-Host "No Vulnerable Chromium Profiles Found"
        Write-Host ""
        Write-Host "CPEV Status: $false"
    }

}

Get-CPEVStatus