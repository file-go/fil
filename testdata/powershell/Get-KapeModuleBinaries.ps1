<#
.SYNOPSIS
    This script will discover and download all available EXE, ZIP, and PS1 files referenced in KAPE Module files and download them to $Dest
    or optionally can be fed a txt file containing URLs to download.
.DESCRIPTION
    This script will discover and download all available EXE, ZIP, and PS1 files referenced in KAPE Module files and download them to $Dest
    or optionally can be fed a txt file containing URLs to download.
    A file will also be created in $Dest that tracks the SHA-1 of each file, so rerunning the script will only download new versions. 
    To redownload, remove lines from or delete the CSV file created under $Dest and rerun. Note this only works for Eric Zimmerman's tools. All others will be downloaded each time.
.PARAMETER Dest
    The path you want to save the programs to. Typically this will be the Bin folder in your KAPE\Modules directory
.PARAMETER ModulePath
    The path containing KAPE module files.
.PARAMETER CreateBinaryList
    Optional switch which scans mkape file and dumps binary urls found to console.
.PARAMETER UseBinaryList
    Optional switch to enable use of txt file to specify which binaries to download.  
.PARAMETER BinaryListPath
    The path of txt file containing Binary URLs.  
.EXAMPLE
    PS C:\Tools> .\Get-KapeModuleBinaries.ps1 -Dest "C:\Forensic Program Files\Zimmerman\Kape\Modules\Bin" -ModulePath "C:\Forensic Program Files\Zimmerman\Kape\Modules"
    Downloads/extracts and saves binaries and binary details to "C:\Forensic Program Files\Zimmerman\Kape\Modules\Bin" directory.
.EXAMPLE
    PS C:\Tools> .\Get-KapeModuleBinaries.ps1 -ModulePath "C:\Forensic Program Files\Zimmerman\Kape\Modules" -CreateBinaryList
    Scans modules directory for mkape files, extracts URLs and dumps to console. This can be used to create a text file for use 
    with the -UseBinaryList and -BinaryList path parameters or just to verify which tools will be downloaded prior to running
.EXAMPLE
    PS C:\Tools> .\Get-KapeModuleBinaries.ps1 -Dest "C:\Forensic Program Files\Zimmerman\Kape\Modules\Bin" -UseBinaryList -BinaryListPath C:\tools\binarylist.txt
    Downloads/extracts and saves binaries and binary details for files specified in C:\tools\binarylist.txt to C:\Forensic Program Files\Zimmerman\Kape\Modules\Bin directory.
.NOTES
    Author: Mike Cary
    This script is a fork of Eric Zimmerman's Get-ZimmermanTools script which has been modified to parse mkape files or other txt files for urls to download
#>

[Cmdletbinding()]
Param
(
    [Parameter()]
    [string]$Dest= (Resolve-Path "."), # Where to save programs to
    [Parameter()]
    [string]$ModulePath, # Path to Kape Modules directory
    [Parameter()]
    [switch]$CreateBinaryList, # Extracts list of Binary URLs and dumps to console
    [Parameter()]	
    [switch]$UseBinaryList, # Optional switch to enable use of txt file to specify which binaries to download
    [string]$BinaryListPath # Path of txt file containing Binary URLs
)

# Some download sources require TLS 1.2 which PowerShell doesn't support out of the box so we are adding that here
function Enable-SSLRequirements
{
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
}
Enable-SSLRequirements

Write-Host "`nThis script will automate the downloading of binaries used by KAPE module files to $Dest" -BackgroundColor Blue

$newInstall = $false

if(!(Test-Path -Path $Dest ))
{
    write-host $Dest " does not exist. Creating..."
    New-Item -ItemType directory -Path $Dest > $null

    $newInstall = $true
}


$WebKeyCollection = @()

$localDetailsFile = Join-Path $Dest -ChildPath "!!!RemoteFileDetails.csv"

if (Test-Path -Path $localDetailsFile)
{
    write-host "Loading local details from '$Dest'..."
    $LocalKeyCollection = Import-Csv -Path $localDetailsFile
}

$toDownload = @()

# Check if $UseBinaryList switch was used and import binary URLs
if($UseBinaryList){
    Try
    {
        $BinaryContent = Get-Content $BinaryListPath -ErrorAction Stop
    }
    Catch
    {
        Write-Host "Unable to import list of Binary URLs. Verify file exists in $BinaryListPath or that you have access to this file"
    }
        
        $progressPreference = 'Continue'
        $regex = [regex] '(?i)\b(http.)://[-A-Z0-9+&@#/%?=~_|$!:,.;]*[A-Z0-9+&@#/%=~_|$].(zip|txt|ps1|exe)'
        $matchdetails = $regex.Match($BinaryContent)  
}

#If $CreateBinaryList switch is used dump list of Binary URLs to console
elseif($CreateBinaryList){
    Write-Host "`nDumping list of Binary URLs to console" -BackgroundColor Blue
    try
    {
        $mkapePath = Get-ChildItem $modulePath -Recurse -Filter *.mkape -ErrorAction Stop
        $mkapeContent = Get-Content $mkapePath.FullName  -ErrorAction Stop
    }
    catch
    {
        Write-Host "Unable to import list of Binary URLs. Verify path to modules folder is correct or that you have access to this directory" -ForegroundColor Yellow
    } 

    $progressPreference = 'Continue'
    $regex = [regex] '(?i)\b(http.)://[-A-Z0-9+&@#/%?=~_|$!:,.;]*[A-Z0-9+&@#/%=~_|$].(zip|txt|ps1|exe)'
    $matchdetails = $regex.Matches($mkapeContent) | Select-Object -Unique

    Write-Output $matchdetails.value
    break
}
# If $UseBinaryList switch wasn't used, scan mkape files for binary URLs and download
else
{
    $progressPreference = 'silentlyContinue'
    try
    {
        $mkapePath = Get-ChildItem $modulePath -Recurse -Filter *.mkape -ErrorAction Stop
        $mkapeContent = Get-Content $mkapePath.FullName  -ErrorAction Stop
    }
    catch
    {
        Write-Host "Unable to import list of Binary URLs. Verify path to modules folder is correct or that you have access to this directory" -ForegroundColor Yellow
    } 

    $progressPreference = 'Continue'
    $regex = [regex] '(?i)\b(http.)://[-A-Z0-9+&@#/%?=~_|$!:,.;]*[A-Z0-9+&@#/%=~_|$].(zip|txt|ps1|exe)'
    $matchdetails = $regex.Match($mkapeContent)
    
    
     
}

write-host "Getting available programs..."
$progressPreference = 'silentlyContinue'
while ($matchdetails.Success) {
    try
    {
        $headers = Invoke-WebRequest -Uri $matchdetails.Value -UseBasicParsing -Method Head -ErrorAction SilentlyContinue
        
        # Checking to verify data was returned before updating $headers variable
        if ($headers -ne $null){
            $headers = $headers.headers
        }
    }
    catch
    {
        $headers = @{}
        $headers."x-bz-content-sha1" = "n/a"
        $headers.'Content-Length' = "n/a"
        $headers."x-bz-file-name" = $matchdetails.Value | Split-Path -Leaf
    }

    # Eric's tools have the hash available in the header so we can check these to see if we have the current version already
    if($matchdetails.Value -like '*EricZimmermanTools*') {
        $getUrl = $matchdetails.Value
        $sha = $headers["x-bz-content-sha1"]
        $name = $headers["x-bz-file-name"]
        $size = $headers["Content-Length"]

        $details = @{            
            Name     = $name            
            SHA1     = $sha                 
            URL     = $getUrl
            Size    = $size
            }                           
    }
    # Downloading 
    else
    {
        $getUrl = $matchdetails.Value
        $sha = "N/A"
        $name = $matchdetails.Value | Split-Path -Leaf

        # test to verify $name doesn't contain illegal characters for a file name
        $name = $name.split([IO.Path]::GetInvalidFileNameChars()) -join '_'

        $size = $headers["Content-Length"]


        $details = @{            
            Name     = $name            
            SHA1     = $sha                 
            URL     = $getUrl
            Size    = $size
            }   
    }
    $webKeyCollection += New-Object PSObject -Property $details  

    $matchdetails = $matchdetails.NextMatch()
} 
$progressPreference = 'Continue'

$WebKeyCollection = $WebKeyCollection | Select-Object * -Unique

Foreach ($webKey in $webKeyCollection)
{
    if ($newInstall)
    {
        $toDownload+= $webKey
        continue    
    }

    $localFile = $LocalKeyCollection | Where-Object {$_.Name -eq $webKey.Name}

    if ($null -eq $localFile -or $localFile.SHA1 -ne $webKey.SHA1 -or $localFile.SHA1 -eq "N/A")
    {
        #Needs to be downloaded since file doesn't exist, SHA is different, or SHA is not in header to compare
        $toDownload+= $webKey
    }
}

if ($toDownload.Count -eq 0)
{
    write-host "`nAll files current. Exiting.`n" -BackgroundColor Blue
    return
}
 
$downloadedOK = @()

foreach($td in $toDownload)
{
    try 
    {
        $dUrl = $td.URL
        $size = $td.Size
        $name = $td.Name
        write-host "Downloading $name (Size: $size)" -ForegroundColor Green
        $destFile = Join-Path -Path $dest -ChildPath $td.Name

        $progressPreference = 'silentlyContinue'
        try
        {
            Invoke-WebRequest -Uri $dUrl -OutFile $destFile -ErrorAction Stop -UseBasicParsing
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Host "Error downloading $name : ($ErrorMessage). Verify Binary URL is correct and try again" -ForegroundColor Yellow
            continue
        }
    
        $downloadedOK += $td

	    if ( $name.endswith("zip") )  
	    {
	        # Test for Archiving cmdlets and if installed, use instead of 7zip
            if (!(Get-Command Expand-Archive -ErrorAction SilentlyContinue)){
                Write-Host "Archive Cmdlets not found. Verify PowerShell version 5 or greater is installed" -ForegroundColor Yellow
                return
            }
            # Archiving cmdlets found so 7zip will not be used
            else
            {
                $global:progressPreference = 'silentlyContinue'
                try
                {  
                    Expand-Archive -Path $destFile -DestinationPath $Dest -Force -ErrorAction Stop
                }
                catch
                {
                    write-host "Unable to extract file:$destFile. Verify file is not in use and that you have access to $Dest." -ForegroundColor Yellow
                }
            }
	    }     
    }
    catch 
    {
        $ErrorMessage = $_.Exception.Message
        write-host "Error downloading $name : ($ErrorMessage). Verify Binary URL is correct and try again" -ForegroundColor Yellow
    }
    finally 
    {
        $progressPreference = 'Continue'
        if ( $name -ne $null){
	        if ( $name.endswith("zip") )  
	        {
	            try
                {  
                    remove-item -Path $destFile -ErrorAction SilentlyContinue
                }
                catch
                {
                    write-host "Unable to remove item: $destFile"
                }
	        }
        } 
        
    }
}

#Downloaded ok contains new stuff, but we need to account for existing stuff too
foreach($webItems in $webKeyCollection)
{
    #Check what we have locally to see if it also contains what is in the web collection
    $localFile = $LocalKeyCollection | Where-Object {$_.SHA1 -eq $webItems.SHA1}

    #if its not null, we have a local file match against what is on the website, so its ok
    
    if ($null -ne $localFile)
    {
        #consider it downloaded since SHAs match
        $downloadedOK+=$webItems
    }
}

# Doing some cleanup to remove files not needed by KAPE and reorganize directory names and structure in line with modules

# EvtxECmd Directory rename

# Check to make sure \EvtxExplorer is in $dest before doing anything
if (Test-Path "$Dest\EvtxExplorer"){
    # Rename EvtxExplorer directory to EvtxECmd to match path in EvtxECmd.mkape
    try
    {
        Rename-Item -Path "$Dest\EvtxExplorer" -NewName "$Dest\EvtxECmd" -Force -ErrorAction Stop
    }
    catch
    {
        Write-Host "Unable to rename $Dest\EvtxExplorer to $Dest\EvtxECmd. Directory may need to be manually renamed for EvtxECmd.mkape to function properly"
    }
}

# Registry Explorer Cleanup and Reorg

# Check to make sure \RegistryExplorer is in $dest before doing anything
if (Test-Path "$Dest\RegistryExplorer"){
    $reCmdDir = "$dest\ReCmd"
    if(!(Test-Path -Path $ReCmdDir))
    {
        try
        {
            New-Item -ItemType directory -Path $ReCmdDir -ErrorAction Stop > $null
        }
        catch
        {
            Write-Host "Unable to create directory path: $RECmdDir. You may need to manually create \Kape\Modules\Bin\ReCmd" -ForegroundColor Yellow
        }
    } 

    $reCmdChanges = @("$Dest\RegistryExplorer\ReCmd.exe","$Dest\RegistryExplorer\BatchExamples\*.reb","$Dest\RegistryExplorer\Plugins")

    foreach($change in $reCmdChanges) {
        try
        {
            Move-Item -Path $change -Destination $ReCmdDir -Force -ErrorAction Stop
        }
        catch
        {
            Write-Host "Unable to move $change to $RECmdDir. You may need to manually move this for RECmd.mkape to function properly" -ForegroundColor Yellow
        }
    }

    # Delete RegistryExplorer Directory
    try
    {
        Remove-Item -Path "$Dest\RegistryExplorer" -Recurse -Force -ErrorAction Stop
    }
    catch
    {
        Write-Host "Unable to delete $Dest\RegistryExplorer" -ForegroundColor Yellow
    }
}

# Additonal cleanup of tools that must reside directly in \Kape\Modules\Bin
$toolPath = @("$Dest\ShellBagsExplorer\SBECmd.exe","$Dest\win64\densityscout.exe","$Dest\sqlite-tools-win32-x86-3270200\*.exe")

foreach($tool in $toolPath){

    # Check to make sure each $tool is in $dest before doing anything
    if (Test-Path $tool){
        try
        {
            Move-Item -Path $tool -Destination $Dest -Force -ErrorAction Stop
        }
        catch
        {
            Write-Host "Unable to move $tool to $Dest. You may need to manually move this for the module to function properly" -ForegroundColor Yellow
        }
    
        # Delete Tool Directory
        try
        {
            $toolDir = $tool | Split-Path -Parent
            Remove-Item -Path $toolDir -Recurse -Force -ErrorAction Stop
        }
        catch
        {
            Write-Host "Unable to delete $toolDir" -ForegroundColor Yellow
        }    
    }
}

Write-host "`nSaving downloaded version information to $localDetailsFile`n" -ForegroundColor Red
$downloadedOK | export-csv -Path  $localDetailsFile