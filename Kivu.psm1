<#
.Synopsis
   Query VirusTotal for a hash analysis
.DESCRIPTION
   Passes a API and hash to VirusTotal and returns the results.
   The input will accept MD5 or SHA1 hashes or a mix of both. 
.EXAMPLE
   Get-VTResults -Hash 'MD5 or SHA1 hash' -Key 'A VirusTotal API key'
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-VTResult
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Hash to check on VirusTotal
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Hash,

        # Virus Total API key
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $Key,

        # File to write data to
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $OutputFile
    )

    Begin
    {
        $Body = @()
        $Body = @{ resource = $Hash; apikey = $Key }
    
    }
    Process
    {
        $Scan = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $Body
    }
    End
    {
        $Scan | export-csv -Path $ReportPath -Append -NoTypeInformation -Force 
        $Hashlength = $scan.resource.Length
            switch ($Hashlength)
            {
                32 { $hashtype = 'MD5'}
                40 { $hashtype = 'SHA-1'}
                64 { $hashtype = 'SHA-265'}
            }
        
        if ($scan.positives -ge 10) 
        {
            $result = 'Malware'
            $script:ScanResult = @{'Hash' = $Scan.sha256;'HashType' = $hashtype;'Status' = $result;'DateFirstSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'DateLastSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'CaseName' = '';'Filename' = ''}
        }
        if ($scan.positives -lt 10) 
        {
            $result = 'Clean'
            $script:ScanResult = @{'Hash' = $Scan.sha256;'HashType' = $hashtype;'Status' = $result;'DateFirstSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'DateLastSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'CaseName' = '';'Filename' = ''}
        }  
        if ($scan.verbose_msg -eq 'The requested resource is not among the finished, queued or pending scans') 
        {
            $result = 'Unknown'

           
            #insert switch to determine hash type
            

            $script:ScanResult = @{'Hash' = $scan.resource;'HashType' = $hashtype;'Status' = $result;'DateFirstSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'DateLastSeen' = $(Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss");'CaseName' = '';'Filename' = ''}
        }                                                                
                
        
        #write the results to the database
        Set-DBData $script:ScanResult
    }
}

<#
.Synopsis
   Function for sleep with on screen countdown and progress bar
.DESCRIPTION
   Progress bar for start-sleep
.EXAMPLE
   start-sleepcountdown -seconds 5
#>
function Start-SleepCountdown 
    ($seconds) 
    {
        $doneDT = (Get-Date).AddSeconds($seconds)
        while ($doneDT -gt (Get-Date)) 
        {
            $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
            $percent = ($seconds - $secondsLeft) / $seconds * 100
            Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
            [System.Threading.Thread]::Sleep(500)
        }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Submit-HashAnalysis
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Full path to Hash file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $HashPath,

        # Full path to API Key file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $KeyPath,

        # Full path to write output file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        $ReportPath 
       
        )
    Begin
    {
        # Import and validate data
        if ($HashPath -like '*.txt') { $allhashes = Get-Content $hashpath}
        #else {Write-host 'Hash input file must be either .txt or .csv format,' -ForegroundColor Red}
        if ($HashPath -like '*.csv') { $allhashes = Import-Csv  $hashpath}
        #else {Write-host 'Hash input file must be either .txt or .csv format,' -ForegroundColor Red}
        # ^^^^^^^  remarked out until input format is finalized

        if ($KeyPath -like '*.txt') { $APIKeys = Get-Content $KeyPath}
        #else {Write-host 'API key input file must be either .txt or .csv format.' -ForegroundColor Red}
        if ($KeyPath -like '*.csv') { $APIKeys = Import-Csv  $KeyPath}
        #else {Write-host 'API key input file must be either .txt or .csv format.' -ForegroundColor Red}
        # ^^^^^^^  remarked out until input format is finalized

        $APIKeys = Get-Content $KeyPath

        #validate hash and API content
        if ($allhashes.count -gt 0) {Write-Host ($allhashes).count" hashes found in $hashpath." -ForegroundColor Green}
        else 
        {
            Write-Host "No hashes found in file located at $hashpath. `nCannot continue.  Ending job." -ForegroundColor Red
            Break
        }

        if ($APIKeys -gt 0) {Write-Host ($APIKeys).count "API keys will be used to process the hashes." -ForegroundColor Green}
        else
        {
            Write-host "No API Keys found in file located at $APIkeypath. `nCannot continue.  Ending job." -ForegroundColor Red
            Break   
        }

        if (Test-Path -Path $ReportPath) 
        {
            Write-Host "$ReportPath already exists.  The report file should not exists before begining.`nPlease use a new file name." -ForegroundColor Red
            Break
        }

        #Check database to see if Hash is already known
        $script:Hashestorun = @()
        foreach ($checkhash in $allhashes)
        {
            #Write-Host "Checking hash $checkhash    -Check point 1"    ########################################################
            Get-DBData -Hash $checkhash
            if ($Status -eq 'Clean')
            {
                #write to $reportpath that the file is known to be clean
                Write-host "$checkhash is known to be clean." -ForegroundColor Green
            }

            if ($status -eq 'Malware')
            {
                #Write t0 $reportpath that the files is known malware
                Write-host "$checkhash is known to be malware." -ForegroundColor White -BackgroundColor Red
            }
            if ($status -eq 'Unknown')
            {
                #add file to list to be processed.
                Write-host "$checkhash is unknown and will be processed."
                $script:Hashestorun += $checkhash
            }
        }
    }
    Process
    {
        # Submit data to API
        $count = 0      # Sets the initial value of the API key iteration.
        $hash = $null
        foreach ($hash in $script:hashestorun)
        {
            if ($count -eq ($APIKeys.count)){$count = 0}   #resets the API key iteration to the first key
    
            Write-Host "Querying $hash"
            $key = $APIKeys[$count]
            Get-VTResult -Hash $hash -Key $key -OutputFile $ReportPath
            

            $count ++     #increments the API key to use the next key

            if ($count -eq $APIKeys.count)     # pauses the API query for 15 seconds to limit the query to 4 per minute
            {
                Write-Host 'Entering Sleep for 15 seconds' -ForegroundColor Yellow
                Start-Sleepcountdown -Seconds 15.2
            }
        }

    }
    End
    {
        # Count results to confirm completion
        #if ((Import-Csv -Path $ReportPath).count -eq $allhashes.count) {Write-Host "Hash analysis is complete and all hashes were processed and exported to $ReportPath" -ForegroundColor Green}
        #else {Write-Host 'There may have been an issue with processing, please review results.' -ForegroundColor Red}
        Write-Host 'Processing complete.' -ForegroundColor Green
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-DBData
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Hash
    )

    Begin
    {
        $check = $null
        $status = $null
        $DBSplatread = @{
        'ServerInstance' = "$env:COMPUTERNAME\SQLExpress";
        'Database' = 'Hashes';
        'Query' = "Select	* from HashTable Where [Hash] like '$Hash'"}
    }
    Process
    {
        $Check = Invoke-Sqlcmd @DBSplatread
    }
    End
    {
        Switch ($check.status)
        {
            Clean {$script:Status = 'Clean'}
            Malware {$script:Status = 'Malware'}
            Unknown {$script:Status = 'Unknown'}
            $null {$script:Status = 'Unknown'}
        }
     }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Set-DBData
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $script:Scanresult

    )

    Begin
    {
        #check to see if hash already exists
        Get-DBData -Hash $script:ScanResult.Hash
        if ($check -ne $null)
        {
            $splathash = $script:ScanResult.Hash
            $splatstatus =  $script:ScanResult.Status
            $splatdatelastseen = (Get-Date -Format "yyyy-MM-dd hh:mm:ss.sss")
            $splatfilename = $script:ScanResult.Filename
            $writesplatquery = "UPDATE Hashtable 
            SET Status = '$splatstatus', DateLastSeen = '$splatdatelastseen', Filename = CAST(FileName as VARCHAR(MAX)) + '$splatfilename'
            WHERE Hash = '$splathash'"
            $DBSplatinsert = @{
            'ServerInstance' = "$env:COMPUTERNAME\SQLExpress";
            'Database' = 'Hashes';
            'Query' =  $writesplatquery}
        }
        if ($check -eq $null) 
        {
            $splathash = $script:ScanResult.Hash
            $splathashtype = $script:ScanResult.HashType
            $splatstatus =  $script:ScanResult.Status
            $splatdatefirstseen = $script:ScanResult.DateFirstSeen
            $splatdatelastseen = $script:ScanResult.DateLastSeen
            $splatcasename = $script:ScanResult.CaseName
            $splatfilename = $script:ScanResult.Filename
            $writesplatquery = "INSERT INTO Hashtable 
            ([Hash]
            ,[HashType]
            ,[Status]
            ,[DateFirstSeen]
            ,[DateLastSeen]
            ,[CaseName]
            ,[Filename])
            VALUES
            ('$splathash'
            ,'$splathashtype'
            ,'$splatstatus'
            ,'$splatdatefirstseet'
            ,'$splatdatelastseen'
            ,'$splatcasename'
            ,'$splatfilename')
            GO"
            $DBSplatinsert = @{
            'ServerInstance' = "$env:COMPUTERNAME\SQLExpress";
            'Database' = 'Hashes';
            'Query' =  $writesplatquery
            }
        }      
    }
    Process
    {
        Invoke-Sqlcmd @DBSplatinsert
    }
    End
    {
    }
}

<#
 .Synopsis
    Copies standard triage data from a mounted disk image
 .Version
    1.0
 .Change Log
    -Added case name parameter and use it as the folder name for output
 .Proposed Changes
    -Adding Try Catch to all copy items for better error handling and useful output
 .DESCRIPTION
    Copies NTUser, UsrClass, Amcache, webcache, RDP cache, Windows event logs, and computer registry hives from a mounted disk image.
    The script needs three data points to run, the drive letter of the mounted disk image, the drive you would like the data
    exported to, and the name of the computer you are pulling data from.
    The output of the script will be saved to X:\Casename\Computername where X is the destination drive letter specified in the
    command, CaseName is the case specified in the command. and Computername is the name of the computer specified in the command.
 .EXAMPLE - Shorthand
    Get-MountedData X C Desktop01 CaseName
 .EXAMPLE - Verbose
    Get-MountedData -SourceDriveLetter X -DestinationDriveLetter C -ComputerName Desktop01 -CaseName Case
 #>
 function Get-MountedData
 {
     Param
     (
         # Param help description
         [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$false,
                    Position=0)]
         $SourceDriveLetter,

         # Param help description
         [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$false,
                    Position=1)]
         $DestinationDriveLetter,
 
         # Param help description
         [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$false,
                    Position=3)]
         $ComputerName,

         # Param help description
         [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$false,
                    Position=2)]
         $CaseName
    )
     Begin
     {
        Test-AdminRights -Break
     }
     Process
     {
        #Variable concatenation for creating source and destination variables
        
        #$ErrorActionPreference = 'SilentlyContinue'
        $destination = "$destinationDriveLetter"+':\'+"$CaseName\"+$computername+'\'
        $drive = $SourceDriveLetter+':'
        $systemroot = $drive+'\Windows\'
        $userroot = $Drive+'\users'
        
        #Query the users in X:\users

        $users = Get-ChildItem -Path $userroot  -Directory     #  this will not pick up any hidden directories, ie. Public or Default

        foreach ($user in $users.name)    #Iteration through all User directories
        {
            
            #Copy App Cache for user
            $userdestination = $destination+$user+'\'
            $root = $drive+'\'+'users\'+$user+'\'
            $source = $root+'AppData\Local\Microsoft\Windows\Appcache\'
            copy-item $source -Destination $userdestination'AppCache\' -recurse -force -ErrorAction SilentlyContinue

            #Copy Web Cache for user
            $source = $root+'AppData\Local\Microsoft\Windows\webcache\'
            copy-item $source -Destination $userdestination'WebCache\' -recurse -force -ErrorAction SilentlyContinue

            #Copy UsrClass for user
            $source = $root+'AppData\Local\Microsoft\Windows\'
            Copy-Item -Path $source\* -Destination $userdestination'UsrClass\' -force 

            #Copy NTUser for user
            $dest = $userdestination+'NTUser\'
            Get-ChildItem -Path $root -Hidden -File | where name -like 'ntuser*' | select name,DirectoryName,LastWriteTime,FullName | select -ExpandProperty fullname | Copy-Item -Destination $userdestination  -force
            
            #Copy TSCache for user.  This may be empty which is why it is in a try catch for error handling.
            try{
            $source = $root+'AppData\Local\Microsoft\Terminal Server client\Cache\'
            $dest = $userdestination+'TSCache\' 
            Copy-Item -Path $source -Destination $dest -Force -Recurse
            }
            catch{}
        }

        #Copy Windows event logs
        $source = $systemroot+'\system32\winevt\logs\'
        $dest = $destination+'\winevt\'
        Copy-Item -Path $source -Destination $dest -Force -Recurse

        #Copy system registry items
        $source = $systemroot+'\system32\config\*'
        $dest = $destination+'config\'
        Copy-Item -Path $source -Destination $dest -Force 

        #Copy appcompat registry items
        $source = $systemroot+'\appcompat\*'
        $dest = $destination+'config\'
        Copy-Item -Path $source -Destination $dest -Force 
    }
    End
    {
    }
 }

<#
.Synopsis
   Function to check for admin rights and break script if not running as admin
.DESCRIPTION
   Long description
.EXAMPLE
   Test-AdminRights -Break [$True | $False]
.EXAMPLE
   Test-AdminRights
#>
function Test-AdminRights
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([bool])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=0)]
        [Switch]$Break
    )

    Begin
    {
    }
    Process
    {
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”))
        {
            Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
            
            if ($Break -eq $true)
            {
                Write-Warning "Ending Script." 
                Break
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Looks up IP Addresses and saves them into an Excel Format
.DESCRIPTION
   Make sure your Report Path file is an Excel file format like XLSX
   A 2 second delay is run between each IP address look up to prevent
   a rate limit imposed by the API.
.EXAMPLE
   Get-IPGeolocation -IPFilePath .\IPList.txt -ReportPath .\IPReport.xlsx
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-IPGeolocation
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $IPFilePath,

        # Param2 help description
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=1)]
        $ReportPath
    )
    Begin
    {
        if ((Get-InstalledModule -Name ImportExcel -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Host "This function required the ImportExcel module from the PSGallery." -ForegroundColor Red
            $installoption = Read-Host "Whould you like to install it now"
            if ($installoption -like "*y*") 
            {
                Check-AdminRights -Break $true
                Install-Module -Name ImportExcell -Scope AllUsers -Force
            }
        }
        $IPs = Get-Content -Path $IPFilePath
    }
    Process
    {
        $IPsCount = $IPs.count
        $increment = 1
        
        foreach ($IP in $IPs)
        {
            Write-Progress -Activity "Looking up IP Addresses" -Status "Currently looking up $IP" -PercentComplete (($increment / $IPsCount) * 100)  
            #$Data = Invoke-RestMethod -Method Get -Uri "https://ipapi.co/$IP/json/"
            $Data = Invoke-RestMethod -Method Get -Uri "https://api.ipgeolocation.io/ipgeo?apiKey=be8aa3b0902c47079e07d0d120c44665&ip=$IP"
            Start-Sleep -Seconds 2
            $Data | Export-Excel -Path $ReportPath -Append
            $increment ++
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Function to aggregate all SHA1 hashes from KECT data in a specified directory
.DESCRIPTION
   Function to aggregate all SHA1 hashes from KECT data in a specified directory.  Can extract ZIP data if specified.
.EXAMPLE
   Convert-HashLogs -Path X:\CaseFolder\LocationOfExtractedKECTData
.EXAMPLE
   Convert-HashLogs -Path X:\CaseFolder\LocationofKECTZips -Extract $true
#>
function Convert-HashLogs
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=0)]
        $Path,

        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=1)]
        [Switch]
        $Extract
    )

    Begin
    {
        if ($Path -eq $null) {$Path = Get-Location}

        if ($Extract) { Expand-Archive -Path *.zip -OutputPath $Path -ShowProgress}
    }
    Process
    {
        ([System.Collections.Generic.HashSet[string]] $HashList = (Get-ChildItem -Path $Path -Recurse | where name -Like '*sha1hash*').FullName | ForEach-Object {Get-Content $_})
    }
    End
    {
        $HashList | out-file $Path\SHA1HashList.txt
    }
}

<#
.Synopsis
   RegRip all data in a directory
.DESCRIPTION
   Parses all data in a tree for registry data and runs RegRipper on the data.
   Leaves an identically named .txt file in the same location as the registry file.
   Runs all available plugins based on the content of the profile files.
   Requires RegRipper to be placed at the same directory you are operating from
.EXAMPLE
   Use-Regripper -Path .\
#>
function Use-Regripper
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Path to root of data to rip
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Path,

        [Switch]
        $UsrClass,

        [Switch]
        $NTUser,

        [Switch]
        $System,

        [Switch]
        $Security,

        [Switch]
        $AppCompat,

        [Switch]
        $All
    )

    Begin
    {
        Test-AdminRights -Break
        #downloads regripper from GitHub.
        try {Invoke-WebRequest -Uri https://github.com/keydet89/RegRipper2.8/archive/master.zip -OutFile $env:temp\master.zip}
        catch {Write-Warning "Could not download RegRipper from GitHub.  Check to make sure that it has not been updated to a new version."}
        Expand-Archive $env:temp\master.zip -DestinationPath $env:temp 
    }
    Process
    {
        if ($All)
        {
            $UsrClass = $true
            $NTUser = $true
            $System = $true
            $Security = $true
            $AppCompat = $true

        if ($UsrClass)
        {        
            $usrs = (Get-ChildItem -Path $Path -Recurse -Force | where 'name' -like '*usrclass.dat').fullname
            $ErrorActionPreference = 'SilentlyContinue'
            $plugins = get-content -Path .\plugins\usrclass
            foreach ($usr in $usrs)
            {
                $destusr = $usr.Substring(0,$usr.Length-4)+'.txt'
                if (Test-Path $destusr) {Remove-Item -Path $destusr -Force -ErrorAction SilentlyContinue}
                Write-Host "Processing file $usr." -ForegroundColor Green
                foreach ($plugin in $plugins)
                {
                Write-Host "Working on plugin $plugin."
                try{ & "$env:temp\RegRipper2.8-master\rip.exe" -r $usr -p $plugin | out-file $destusr -append }
                catch {}
                }
            }
        }
        
        if ($NTUser)
        {
            $ntusrs = (Get-ChildItem -Path $Path -Recurse -Force | where 'name' -like '*ntuser.dat').fullname
            $ErrorActionPreference = 'SilentlyContinue'
            $plugins = get-content -Path .\plugins\ntuser
            foreach ($ntusr in $ntusrs)
            {
                $destntusr = $ntusr.Substring(0,$ntusr.Length-4)+'.txt'
                if (Test-Path $destntusr) {Remove-Item -Path $destntusr -Force -ErrorAction SilentlyContinue}
                Write-Host "Processing file $ntusr." -ForegroundColor Green
                foreach ($plugin in $plugins)
                                {
                Write-Host "Working on plugin $plugin."
                try { & "$env:temp\RegRipper2.8-master\rip.exe" -r $ntusr -p $plugin | out-file $destntusr -Append }
                catch {}
            }
            }
        }

        if ($System)
        {
            $SystemRegs = (Get-ChildItem -Path $Path -Recurse -Force | where 'name' -eq 'System').fullname
            $plugins = get-content -Path .\plugins\system
            foreach ($system in $systemregs)
            {
                $destsystem = $system.Substring(0,$system.Length-4)+'.txt'
                if (Test-Path $destsystem) {Remove-Item -Path $destsystem -Force -ErrorAction SilentlyContinue}
                Write-Host "Processing file $system." -ForegroundColor Green
                foreach ($plugin in $plugins)
                                {
                Write-Host "Working on plugin $plugin."
                try { & "$env:temp\RegRipper2.8-master\rip.exe" -r $system -p $plugin | out-file $destsystem -Append }
                catch {}
            }
            }
        }

        if ($AppCompat)
        {
            $appcompatRegs = (Get-ChildItem -Path $Path -Recurse -Force | where 'name' -eq 'Amcache').fullname
            $plugins = get-content -Path .\plugins\amcache
            foreach ($amc in $appcompatRegs)
            {
                $destsystem = $amc.Substring(0,$amc.Length-4)+'.txt'
                Write-Host "Processing file $amc." -ForegroundColor Green
                foreach ($plugin in $plugins)
                {
                    Write-Host "Working on plugin $plugin."
                    try { & "$env:temp\RegRipper2.8-master\rip.exe" -r $amc -p $plugin | out-file $destsystem -Append }
                    catch {}
                }
            }
        }

        if ($Security)
        {
            $secRegs = (Get-ChildItem -Path $Path -Recurse -Force | where 'name' -eq 'Security').fullname
            $plugins = get-content -Path .\plugins\security
            foreach ($sec in $secregs)
            {
                $destsec = $sec+'.txt'
                if (Test-Path $destsec) {Remove-Item -Path $destsec -Force -ErrorAction SilentlyContinue}
                Write-Host "Processing file $sec." -ForegroundColor Green
                foreach ($plugin in $plugins)
                {
                    Write-Host "Working on plugin $plugin."
                    try { & "$env:temp\RegRipper2.8-master\rip.exe" -r $sec -p $plugin | out-file $destsec -Append }
                    catch {}
                }
            }
        }
    }
    }
    End
    {
        #cleans up temporary RegRipper installation
        Remove-Item -Path $env:Temp\master.zip -Force
        Remove-Item -Path $env:Temp\RegRipper2.8-master -Force -Recurse
    }
}

<#
.Synopsis
   Decrypt all enc and aesenc files in a given location
.DESCRIPTION
   Requires the files necessary for decryption in the same path as the encrypted files
.EXAMPLE
   Start-KECTDecrypt -Path z:\CaseData\Casefolder\WorkProduct\KECT\Batch1 -Expand $true
.EXAMPLE
   Start-KECTDecrypt -Path z:\CaseData\Casefolder\WorkProduct\KECT\Batch1
#>
function Start-KECTDecrypt
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Specify Path to files
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Path,

        # Specify Extraction Option
        [Switch]
        $Extract
    )

    Begin
    {
        (Get-ChildItem $Path | where name -like '*.enc').name | Out-File $Path\Decrypt.txt -Encoding UTF8NoBOM
        (Get-ChildItem $Path | where name -like '*.aesenc').name | Out-File $Path\Decryptaes.txt -Encoding UTF8NoBOM
    }
    Process
    {
        & $Path\batchdecrypt.bat
    }
    End
    {
        if ($Extract)
        {
            $zips = (Get-ChildItem -Path $Path | where Name -like '*.zip').FullName
            foreach ($zip in $zips)
            {
                Expand-Archive -Path $zip -DestinationPath $Path
            }
        }
    }
}
