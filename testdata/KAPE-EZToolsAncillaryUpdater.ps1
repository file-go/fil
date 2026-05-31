<#
	.SYNOPSIS
		Keep KAPE and all the included EZ Tools updated! Be sure to run this script from the root of your KAPE folder, i.e., where kape.exe, gkape.exe, Targets, Modules, and Documentation folders exists
	
	.DESCRIPTION
		Updates the following:
		
		KAPE binary (.KAPE\kape.exe) - https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
		KAPE Targets (.\KAPE\Targets\*.tkape) - https://github.com/EricZimmerman/KapeFiles/tree/master/Targets
		KAPE Modules (.\KAPE\Modules\*.mkape) - https://github.com/EricZimmerman/KapeFiles/tree/master/Modules
		RECmd Batch Files (.\KAPE\Modules\bin\RECmd\BatchExamples\*.reb) - https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples
		EvtxECmd Maps (.\KAPE\Modules\bin\EvtxECmd\Maps\*.map) - https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps
		SQLECmd Maps (.\KAPE\Modules\bin\SQLECmd\Maps\*.smap) - https://github.com/EricZimmerman/SQLECmd/tree/master/SQLMap/Maps
		All other EZ Tools used by KAPE in the !EZParser Module
		
	.USAGE
		As of 4.0, this script will only download .NET 6 tools, so you can just run the script in your .\KAPE folder!
		
	.CHANGELOG
		1.0 - (Sep 09, 2021) Initial release
		2.0 - (Oct 22, 2021) Updated version of KAPE-EZToolsAncillaryUpdater PowerShell script which leverages Get-KAPEUpdate.ps1 and Get-ZimmermanTools.ps1 as well as other various --sync commands to keep all of KAPE and the command line EZ Tools updated to their fullest potential with minimal effort. Signed script with certificate
		3.0 - (Feb 22, 2022) Updated version of KAPE-EZToolsAncillaryUpdater PowerShell script which gives user option to leverage either the .NET 4 or .NET 6 version of EZ Tools in the .\KAPE\Modules\bin folder. Changed logic so EZ Tools are downloaded using the script from .\KAPE\Modules\bin rather than $PSScriptRoot for cleaner operation and less chance for issues. Added changelog. Added logging capabilities
		3.1 - (Mar 17, 2022) Added a "silent" parameter that disables the progress bar and exits the script without pausing in the end
		3.2 - (Apr 04, 2022) Updated Move-EZToolNET6 to use glob searching instead of hardcoded folder and file paths
		3.3 - (Apr 25, 2022) Updated Move-EZToolsNET6 to correct Issue #9 - https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater/issues/9. Also updated content and formatting of some of the comments
		3.4 - (Jun 24, 2022) Added version checker for the script - https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater/issues/11. Added new messages re: GitHub repositories to follow at the end of each successful run
		3.5 - (Jul 27, 2022) Bug fix for version checker added in 3.4 - https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater/pull/15
		3.6 - (Aug 17, 2022) Added iisGeolocate now that a KAPE Module exists for it, updated comments and log messages
		4.0 - (June 13, 2023) Made adjustments to script based on Get-ZimmermanTools.ps1 update - https://github.com/EricZimmerman/Get-ZimmermanTools/commit/c40e8ddc8df5a210c5d9155194e602a81532f23d, script now defaults to .NET 6, modifed lots of comments, variables, etc, and overall made the script more readable and maintainable
		4.1 - (June 16, 2023) Minor adjustments based on feedback from version 4.0. Additionally, added script info to the log output
		4.2 - (August 04, 2023) Added PowerShell 5 requirement to avoid any potential complications
	
	.PARAMETER silent
		Disable the progress bar and exit the script without pausing in the end
	
	.PARAMETER DoNotUpdate
		Use this if you do not want to check for and update the script
	
	.NOTES
		===========================================================================
		Created with:	 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.201
		Created on:   		2022-02-22 23:29
		Created by:	   		Andrew Rathbun
		Organization: 		Kroll
		Filename:			KAPE-EZToolsAncillaryUpdater.ps1
		GitHub:				https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater
		Version:			4.2
		===========================================================================
#>

#Requires -Version 5

param
(
	[Parameter(HelpMessage = 'Disable the progress bar and exit the script without pausing in the end')]
	[Switch]$silent,
	[Parameter(HelpMessage = 'Use this if you do not want to check for and update the script')]
	[Switch]$DoNotUpdate
)

function Get-TimeStamp
{
	return '[{0:yyyy/MM/dd} {0:HH:mm:ss}]' -f (Get-Date)
}

function Log
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$logFilePath,
		[string]$msg
	)
	
	if ([string]::IsNullOrWhiteSpace($logFilePath))
	{
		Log -logFilePath $logFilePath -msg "Error: logFilePath parameter is null or empty"
		return
	}
	
	$msg = Write-Output "$(Get-TimeStamp) | $msg"
	Out-File $logFilePath -Append -InputObject $msg -Encoding ASCII
	Write-Host $msg
}

$script:logFilePath = Join-Path $PSScriptRoot -ChildPath "KAPEUpdateLog.log"

if ($silent)
{
	$ProgressPreference = 'SilentlyContinue'
}

function Start-Script
{
	[CmdletBinding()]
	param ()
	
	# Establishes stopwatch to keep track of execution duration of this script
	$script:stopwatch = [system.diagnostics.stopwatch]::StartNew()
	
	$Stopwatch.Start()
	
	Log -logFilePath $logFilePath -msg ' --- Beginning of session ---' # start of Log
	
	Set-ExecutionPolicy Bypass -Scope Process
	
	# Let's get some script info and provide it to the end user for the purpose of the log
	# establish name of script to pass to Log-ToFile Module, so it outputs to the correctly named log file
	$scriptPath = $PSCommandPath
	
	$scriptNameWithoutExtension = (Split-Path -Path $scriptPath -Leaf).TrimEnd('.ps1') # this isn't currently used
	$scriptName = Split-Path -Path $scriptPath -Leaf
	
	$fileInfo = Get-Item $scriptPath
	$fileSizeInBytes = $fileInfo.Length
	$fileSizeInMegabytes = $fileSizeInBytes / 1MB
	
	$signature = Get-AuthenticodeSignature $scriptPath
	
	if ($signature -and $signature.SignerCertificate)
	{
		$lastSignedTime = $signature.SignerCertificate.NotAfter
	}
	else
	{
		$lastSignedTime = "Invalid or not signed"
	}
	
	$fileHash = (Get-FileHash -Path $scriptPath -Algorithm SHA1).Hash
	
	$fileSizeFormatted = "{0:N2}" -f $fileSizeInMegabytes
	
	# Output all of the above stats about this script. Examples are in comments at end of each line
	Log -logFilePath $logFilePath -msg "Script Name: $scriptName" # [2023-06-13 22:23:13] | Script Name: KAPE-EZToolsAncillaryUpdater.ps1
	Log -logFilePath $logFilePath -msg "Full Path: $scriptPath" # [2023-06-13 22:23:13] | Full Path: D:\KAPE-EZToolsAncillaryUpdater\KAPE-EZToolsAncillaryUpdater.ps1
	Log -logFilePath $logFilePath -msg "Last Modified Date: $($fileInfo.LastWriteTime)" # [2023-06-13 22:23:13] | Last Modified Date: 06/13/2023 22:23:07
	Log -logFilePath $logFilePath -msg "File Size: $fileSizeInBytes bytes | $fileSizeFormatted MB" # [2023-06-13 22:23:13] | File Size: 43655 bytes | 0.04 MB
	Log -logFilePath $logFilePath -msg "Certificate Expiration: $lastSignedTime" # [2023-06-13 22:23:13] | Certificate Expiration: 01/26/2025 18:59:59
	Log -logFilePath $logFilePath -msg "SHA1 Hash: $fileHash" # [2023-06-13 22:23:13] | SHA1 Hash: A9E7D1DB7A8C41B9424DEC57297CC9E6
	Log -logFilePath $logFilePath -msg "--------- Script Log ---------"
	
	# Validate that logFilePath exists and shoot a message to the user one way or another
	try
	{
		if (!(Test-Path -Path $logFilePath))
		{
			New-Item -ItemType File -Path $logFilePath -Force | Out-Null
			Log -logFilePath $logFilePath -msg "Created new log file at $logFilePath"
		}
		else
		{
			Log -logFilePath $logFilePath -msg "Log file already exists at $logFilePath"
		}
	}
	catch
	{
		Write-Host $_.Exception.Message
	}
}

function Set-Variables
{
	[CmdletBinding()]
	param ()
	
	# Setting variables the script relies on. Comments show expected values stored within each respective variable
	$script:kapeTargetsFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Targets' # .\KAPE\Targets
	$script:kapeModulesFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Modules' # .\KAPE\Modules
	$script:kapeModulesBin = Join-Path -Path $kapeModulesFolder -ChildPath 'bin' # .\KAPE\Modules\bin
	$script:getZimmermanToolsFolderKape = Join-Path -Path $kapeModulesBin -ChildPath 'ZimmermanTools' # .\KAPE\Modules\bin\ZimmermanTools, also serves as our .NET 4 folder, if needed
	$script:getZimmermanToolsFolderKapeNet6 = Join-Path -Path $getZimmermanToolsFolderKape -ChildPath 'net6' # .\KAPE\Modules\bin\ZimmermanTools\net6
	
	$script:ZTZipFile = 'Get-ZimmermanTools.zip'
	$script:ZTdlUrl = "https://f001.backblazeb2.com/file/EricZimmermanTools/$ZTZipFile" # https://f001.backblazeb2.com/file/EricZimmermanTools\Get-ZimmermanTools.zip
	$script:getZimmermanToolsFolderKapeZip = Join-Path -Path $getZimmermanToolsFolderKape -ChildPath $ZTZipFile # .\KAPE\Modules\bin\ZimmermanTools\Get-ZimmermanTools.zip - this currently doesn't get used...
	$script:kapeDownloadUrl = 'https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape'
	$script:kapeEzToolsAncillaryUpdaterFileName = 'KAPE-EZToolsAncillaryUpdater.ps1'
	$script:getZimmermanToolsFileName = 'Get-ZimmermanTools.ps1'
	$script:getKapeUpdatePs1FileName = 'Get-KAPEUpdate.ps1'
	$script:kape = Join-Path -Path $PSScriptRoot -ChildPath 'kape.exe' # .\KAPE\kape.exe
	$script:getZimmermanToolsZipKape = Join-Path -Path $kapeModulesBin -ChildPath $ZTZipFile # .\KAPE\Modules\bin\Get-ZimmermanTools.zip
	$script:getZimmermanToolsPs1Kape = Join-Path -Path $kapeModulesBin -ChildPath $getZimmermanToolsFileName # .\KAPE\Modules\bin\Get-ZimmermanTools.ps1
	
	# setting variables for EZ Tools binaries, folders, and folders containing ancillary files within .\KAPE\Modules\bin
	$script:kapeRecmd = Join-Path $kapeModulesBin -ChildPath 'RECmd' #.\KAPE\Modules\bin\RECmd
	$script:kapeRecmdExe = Get-ChildItem $kapeRecmd -Filter 'RECmd.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName #.\KAPE\Modules\bin\RECmd\RECmd.exe
	$script:kapeRecmdBatchExamples = Join-Path $kapeRecmd -ChildPath 'BatchExamples' #.\KAPE\Modules\bin\RECmd\BatchExamples
	$script:kapeEvtxECmd = Join-Path $kapeModulesBin -ChildPath 'EvtxECmd' #.\KAPE\Modules\bin\EvtxECmd
	$script:kapeEvtxECmdExe = Get-ChildItem $kapeEvtxECmd -Filter 'EvtxECmd.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName #.\KAPE\Modules\bin\EvtxECmd\EvtxECmd.exe
	$script:kapeEvtxECmdMaps = Join-Path $kapeEvtxECmd -ChildPath 'Maps' #.\KAPE\Modules\bin\EvtxECmd\Maps
	$script:kapeSQLECmd = Join-Path $kapeModulesBin -ChildPath 'SQLECmd' #.\KAPE\Modules\bin\SQLECmd
	$script:kapeSQLECmdExe = Get-ChildItem $kapeSQLECmd -Filter 'SQLECmd.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName #.\KAPE\Modules\bin\SQLECmd\SQLECmd.exe
	$script:kapeSQLECmdMaps = Join-Path $kapeSQLECmd -ChildPath 'Maps' #.\KAPE\Modules\bin\SQLECmd\Maps
}

<#
	.SYNOPSIS
		Updates the KAPE binary (kape.exe)

	.DESCRIPTION
		Uses the preexisting .\Get-KAPEUpdate.ps1 script to update the KAPE binary (kape.exe)
#>
function Get-KAPEUpdateEXE
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- Update KAPE ---'
	
	$script:getKapeUpdatePs1 = Get-ChildItem -Path $PSScriptRoot -Filter $getKapeUpdatePs1FileName # .\KAPE\Get-KAPEUpdate.ps1
	
	if ($null -ne $getKapeUpdatePs1)
	{
		Log -logFilePath $logFilePath -msg "Running $getKapeUpdatePs1FileName to update KAPE to the latest binary"
		try
		{
			# Start-Process is used here to execute the PowerShell script
			Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$($getKapeUpdatePs1.FullName)`"" -NoNewWindow -Wait
		}
		catch
		{
			Log -logFilePath $logFilePath -msg "Error when running Get-KAPEUpdate.ps1: $_"
			Log -logFilePath $logFilePath -msg "KAPE was not updated properly, please try again"
			break
		}
	}
	else
	{
		Log -logFilePath $logFilePath -msg "$getKapeUpdatePs1FileName not found, please go download KAPE from $kapeDownloadUrl"
		exit
	}
}

<#
	.SYNOPSIS
		Makes sure the KAPE-EZToolsAncillaryUpdater.ps1 script is updated!

	.DESCRIPTION
		Checks the latest version of this updater and updates if there is a newer version and $DoNotUpdate is $false
#>
function Get-LatestEZToolsUpdater
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- KAPE-EZToolsAncillaryUpdater.ps1 ---'
	
	# First check the version of the current script show line number of match
	$currentScriptVersion = Get-Content $('.\KAPE-EZToolsAncillaryUpdater.ps1') | Select-String -SimpleMatch 'Version:' | Select-Object -First 1 # Version: 3.7
	$versionString = $currentScriptVersion.ToString().Split(':')[1].Trim() # Split by colon and remove leading/trailing spaces
	[System.Single]$CurrentScriptVersionNumber = $versionString # 3.7
	try
	{
		Log -logFilePath $logFilePath -msg "Current version of this script is $CurrentScriptVersionNumber"
	}
	catch
	{
		Log -logFilePath $logFilePath -msg "Caught an error: $_"
	}
	
	# Now get the latest version from GitHub
	$script:kapeEzToolsAncillaryUpdaterReleasesUrl = 'https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater/releases/latest'
	$webRequest = Invoke-WebRequest -Uri $kapeEzToolsAncillaryUpdaterReleasesUrl -UseBasicParsing
	$strings = $webRequest.RawContent
	$script:kapeEzToolsAncillaryUpdaterPattern = 'EZToolsAncillaryUpdater/releases/tag/[0-9].[0-9]+'
	$latestVersion = $strings | Select-String -Pattern $kapeEzToolsAncillaryUpdaterPattern | Select-Object -First 1
	$latestVersionToSplit = $latestVersion.Matches[0].Value
	[System.Single]$LatestVersionNumber = $latestVersionToSplit.Split('/')[-1]
	Log -logFilePath $logFilePath -msg "Latest version of this script is $LatestVersionNumber"
	
	if ($($CurrentScriptVersionNumber -lt $LatestVersionNumber) -and $($DoNotUpdate -eq $false))
	{
		Log -logFilePath $logFilePath -msg 'Updating script to the latest version'
		
		# Start a new PowerShell process so we can replace the existing file and run the new script
		$script:kapeEzToolsAncillaryUpdaterScriptUrl = 'https://raw.githubusercontent.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater/main/KAPE-EZToolsAncillaryUpdater.ps1'
		$script:kapeEzToolsAncillaryUpdaterOutFile = Join-Path -Path $PSScriptRoot -ChildPath 'KAPE-EZToolsAncillaryUpdater.ps1'
		
		try
		{
			Invoke-WebRequest -Uri $kapeEzToolsAncillaryUpdaterScriptUrl -OutFile $kapeEzToolsAncillaryUpdaterOutFile -UseBasicParsing -ErrorAction Stop
		}
		catch
		{
			Log -logFilePath $logFilePath -msg 'Failed to download updated script'
			Log -logFilePath $logFilePath -msg $_.Exception.Message
			Exit
		}
		
		Log -logFilePath $logFilePath -msg "Successfully updated script to $CurrentScriptVersionNumber"
		Log -logFilePath $logFilePath -msg 'Starting updated script in new window'
		
		# Store the arguments in a variable
		$argList = "$kapeEzToolsAncillaryUpdaterOutFile" # no netVersion specified which defaults to .NET 6 tools as of 3.7
		if ($PSBoundParameters.Keys.Contains('silent'))
		{
			$argList += " $true"
		}
		
		# Output a message with the command that's being executed
		Log -logFilePath $logFilePath -msg "Executing: Start-Process PowerShell -ArgumentList `"$argList`""
		
		# Execute the command
		Start-Process PowerShell -ArgumentList $argList
		
		Log -logFilePath $logFilePath -msg 'Please observe the script in the new window'
		Log -logFilePath $logFilePath -msg 'Exiting old script'
		Exit
	}
	else
	{
		Log -logFilePath $logFilePath -msg 'Script is current'
	}
}

<#
	.SYNOPSIS
		Downloads all EZ Tools!

	.DESCRIPTION
		Downloads Get-ZimmermanTools.zip, extracts Get-ZimmermanTools.ps1 from the ZIP file into .\KAPE\Modules\bin\ZimmermanTools
#>
function Get-ZimmermanTools
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- Get-ZimmermanTools.ps1 ---'
	
	# Get all instances of !!!RemoteFileDetails.csv from $PSScriptRoot recursively
	$remoteFileDetailsCSVs = Get-ChildItem -Path $PSScriptRoot -Filter "!!!RemoteFileDetails.csv" -Recurse
	
	# Iterate over each file and remove it forcefully
	foreach ($remoteFileDetailsCSV in $remoteFileDetailsCSVs)
	{
		# Check if the file exists before trying to remove it
		if (Test-Path $remoteFileDetailsCSV.FullName)
		{
			# Remove the file
			Remove-Item -Path $remoteFileDetailsCSV.FullName -Force
			
			# Confirm the file was removed
			if (Test-Path $remoteFileDetailsCSV.FullName)
			{
				Log -logFilePath $logFilePath -msg "Warning: Failed to delete $($remoteFileDetailsCSV.FullName)"
			}
			else
			{
				Log -logFilePath $logFilePath -msg "Deleted $($remoteFileDetailsCSV.FullName)"
			}
		}
	}
	
	# if .\KAPE\Modules\bin\ZimmermanTools doesn't exist, create it!
	Log -logFilePath $logFilePath -msg "Checking if $getZimmermanToolsFolderKape exists"
	
	if (-not (Test-Path $getZimmermanToolsFolderKape))
	{
		Log -logFilePath $logFilePath -msg "Creating $getZimmermanToolsFolderKape"
		New-Item -ItemType Directory -Path $getZimmermanToolsFolderKape | Out-Null
	}
	else
	{
		Log -logFilePath $logFilePath -msg "$getZimmermanToolsFolderKape already exists!"
	}
	
	# -Dest .\KAPE\Modules\bin\ZimmermanTools
	$scriptArgs = @{
		Dest = "$getZimmermanToolsFolderKape"
	}
	
	Log -logFilePath $logFilePath -msg "Downloading $ZTZipFile from $ZTdlUrl to $kapeModulesBin" # message saying we're downloading Get-ZimmermanTools.zip to .\KAPE\Modules\bin
	
	try
	{
		Start-BitsTransfer -Source $ZTdlUrl -Destination $kapeModulesBin -ErrorAction Stop
	}
	catch
	{
		Log -logFilePath $logFilePath -msg "Failed to download $ZTZipFile from $ZTdlUrl. Error: $($_.Exception.Message)"
	}
	
	Log -logFilePath $logFilePath -msg "Extracting $ZTZipFile from $kapeModulesBin to $kapeModulesBin" # extracting Get-ZimmermanTools.zip from .\KAPE\Modules\bin to .\KAPE\Modules\bin
	
	Expand-Archive -Path "$getZimmermanToolsZipKape" -DestinationPath "$kapeModulesBin" -Force # actually expanding Get-ZimmermanTools.zip to .\KAPE\Modules\bin
	
	Log -logFilePath $logFilePath -msg "Moving $getZimmermanToolsFileName from $kapeModulesBin to $getZimmermanToolsFolderKape"
	
	$getZimmermanToolsPs1 = (Get-ChildItem -Path $kapeModulesBin -Filter $getZimmermanToolsFileName).FullName
	
	# Move Get-ZimmermanTools.ps1 from .\KAPE\Modules\bin to .\KAPE\Modules\bin\ZimmermanTools
	Move-Item -Path $getZimmermanToolsPs1 -Destination $getZimmermanToolsFolderKape -Force
	
	$getZimmermanToolsPs1ZT = (Get-ChildItem -Path $getZimmermanToolsFolderKape -Filter $getZimmermanToolsFileName).FullName
	
	# Check if file was moved successfully
	if (-not (Test-Path "$getZimmermanToolsPs1ZT"))
	{
		Log -logFilePath $logFilePath -msg "Failed to move $getZimmermanToolsFileName from $kapeModulesBin to $getZimmermanToolsFolderKape"
	}
	else
	{
		Log -logFilePath $logFilePath -msg "Successfully moved $getZimmermanToolsFileName from $kapeModulesBin to $getZimmermanToolsFolderKape"
	}
	
	Start-Sleep -Seconds 1
	
	Log -logFilePath $logFilePath -msg "Running $getZimmermanToolsFileName! Downloading .NET 6 version of EZ Tools to $getZimmermanToolsFolderKape"
	
	Log -logFilePath $logFilePath -msg "Running script at path $getZimmermanToolsPs1ZT with arguments -Dest $($scriptArgs.Dest)"
	
	# executing .\KAPE\Modules\bin\Get-ZimmermanTools.ps1 -Dest .\KAPE\Modules\bin\ZimmermanTools
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-File $getZimmermanToolsPs1ZT", "-Dest $($scriptArgs.Dest)" -Wait
	
	Start-Sleep -Seconds 3
}

<#
	.SYNOPSIS
		Sync with GitHub for the latest KAPE Targets and Modules!

	.DESCRIPTION
		This function will download the latest KAPE Targets and Modules from https://github.com/EricZimmerman/KapeFiles

	.NOTES
		Sync works without Admin privileges as of KAPE 1.0.0.3
#>
function Sync-KAPETargetsModules
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- KAPE Sync ---'
	
	if (Test-Path -Path $kape)
	{
		Log -logFilePath $logFilePath -msg 'Syncing KAPE with GitHub for the latest Targets and Modules'
		Start-Process $kape -ArgumentList '--sync' -NoNewWindow -Wait # kape.exe --sync
		Start-Sleep -Seconds 3
	}
	else
	{
		Log -logFilePath $logFilePath -msg "$kape not found, please go download KAPE from $kapeDownloadUrl"
		Exit
	}
}

<#
	.SYNOPSIS
		Sync with GitHub for the latest EvtxECmd Maps!

	.DESCRIPTION
		This function will download the latest EvtxECmd Maps from https://github.com/EricZimmerman/evtx
#>
function Sync-EvtxECmdMaps
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- EvtxECmd Sync ---'
	
	# Check if $kapeEvtxECmdExe holds a value
	if ([string]::IsNullOrEmpty($kapeEvtxECmdExe))
	{
		# Redo the original declaration
		$script:kapeEvtxECmdExe = (Get-ChildItem $kapeEvtxECmd -Filter 'EvtxECmd.exe').FullName
		Log -logFilePath $logFilePath -msg "Located $kapeEvtxECmdExe"
	}
	
	# This deletes the .\KAPE\Modules\bin\EvtxECmd\Maps folder so old Maps don't collide with new Maps
	if (Test-Path -Path $kapeEvtxecmdMaps -PathType Container)
	{
		Remove-Item -Path $kapeEvtxecmdMaps -Recurse -Force
		Log -logFilePath $logFilePath -msg "Deleting $kapeEvtxecmdMaps for a fresh start prior to syncing EvtxECmd with GitHub"
	}
	
	# This ensures all the latest EvtxECmd Maps are downloaded
	Log -logFilePath $logFilePath -msg 'Syncing EvtxECmd with GitHub for the latest Maps'
	
	Start-Process $kapeEvtxECmdExe -ArgumentList '--sync' -NoNewWindow -Wait
	
	Start-Sleep -Seconds 5
}


<#
	.SYNOPSIS
		Sync with GitHub for the latest RECmd Batch files!

	.DESCRIPTION
		This function will download the latest RECmd Batch Files from https://github.com/EricZimmerman/RECmd
#>
function Sync-RECmdBatchFiles
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- RECmd Sync ---'
	
	# Check if $kapeRECmdExe holds a value
	if ([string]::IsNullOrEmpty($kapeRECmdExe))
	{
		# Redo the original declaration
		$script:kapeRECmdExe = (Get-ChildItem $kapeRecmd -Filter 'RECmd.exe').FullName
		Log -logFilePath $logFilePath -msg "Located $kapeRECmdExe"
	}
	
	# This deletes the .\KAPE\Modules\bin\RECmd\BatchExamples folder so old Batch files don't collide with new Batch files
	if (Test-Path -Path $kapeRecmdBatchExamples -PathType Container)
	{
		Remove-Item -Path "$kapeRecmdBatchExamples\*" -Recurse -Force
		Log -logFilePath $logFilePath -msg "Deleting $kapeRecmdBatchExamples for a fresh start prior to syncing RECmd with GitHub"
	}
	
	# This ensures all the latest RECmd Batch files are present on disk
	Log -logFilePath $logFilePath -msg 'Syncing RECmd with GitHub for the latest Maps'
	
	Start-Process $kapeRECmdExe -ArgumentList '--sync' -NoNewWindow -Wait
	
	Start-Sleep -Seconds 3
}

<#
	.SYNOPSIS
		Sync with GitHub for the latest SQLECmd Maps!

	.DESCRIPTION
		This function will download the latest Maps from https://github.com/EricZimmerman/SQLECmd
#>
function Sync-SQLECmdMaps
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- SQLECmd Sync ---'
	
	# Check if $kapeRECmdExe holds a value
	if ([string]::IsNullOrEmpty($kapeSQLECmdExe))
	{
		# Redo the original declaration
		$script:kapeSQLECmdExe = (Get-ChildItem $kapeSQLECmd -Filter 'SQLECmd.exe').FullName
		Log -logFilePath $logFilePath -msg "Located $kapeSQLECmdExe"
	}
	
	# This deletes the .\KAPE\Modules\bin\SQLECmd\Maps folder so old Maps don't collide with new Maps
	if (Test-Path -Path $kapeSQLECmdMaps -PathType Container)
	{
		Remove-Item -Path "$kapeSQLECmdMaps\*" -Recurse -Force
		Log -logFilePath $logFilePath -msg "Deleting $kapeSQLECmdMaps for a fresh start prior to syncing SQLECmd with GitHub"
	}
	
	# This ensures all the latest SQLECmd Maps are downloaded
	Log -logFilePath $logFilePath -msg 'Syncing SQLECmd with GitHub for the latest Maps'
	
	Start-Process $kapeSQLECmdExe -ArgumentList '--sync' -NoNewWindow -Wait
	
	Start-Sleep -Seconds 3
}

<#
	.SYNOPSIS
		Set up KAPE for use with .NET 6 EZ Tools!

	.DESCRIPTION
		Ensures all .NET 6 EZ Tools that were downloaded using Get-ZimmermanTools.ps1 are copied into the correct folders within .\KAPE\Modules\bin
#>
function Move-EZToolsNET6
{
	[CmdletBinding()]
	param ()
	
	# Only run if Get-ZimmermanTools.ps1 has downloaded new .NET 6 tools, otherwise continue on.
	if (Test-Path -Path "$getZimmermanToolsFolderKapeNet6")
	{
		
		Log -logFilePath $logFilePath -msg 'Please ensure you have the latest version of the .NET 6 Runtime installed. You can download it here: https://dotnet.microsoft.com/en-us/download/dotnet/6.0. Please note that the .NET 6 Desktop Runtime includes the Runtime needed for Desktop AND Console applications, aka Registry Explorer AND RECmd, for example'
		
		# Create array of folders to be copied
		$folders = @(
			"$getZimmermanToolsFolderKapeNet6\EvtxECmd",
			"$getZimmermanToolsFolderKapeNet6\RECmd",
			"$getZimmermanToolsFolderKapeNet6\SQLECmd",
			"$getZimmermanToolsFolderKapeNet6\iisGeolocate"
		)
		
		Log -logFilePath $logFilePath -msg ' --- EZ Tools Folder Copy ---'
		
		# Copy each folder that exists
		$folderSuccess = @()
		foreach ($folder in $folders)
		{
			if (Test-Path -Path $folder)
			{
				Copy-Item -Path $folder -Destination $kapeModulesBin -Recurse -Force
				$folderSuccess += $folder.Split('\')[-1]
				Log -logFilePath $logFilePath -msg "Copying $folder and all contents to $kapeModulesBin"
			}
		}
		
		# Log only the folders that were copied
		Log -logFilePath $logFilePath -msg "Copied $($folderSuccess -join ', ') and all associated ancillary files to $kapeModulesBin successfully"
		
		Log -logFilePath $logFilePath -msg ' --- EZ Tools File Copy ---'
		
		# Create an array of the file extensions to copy
		$fileExts = @('*.dll', '*.exe', '*.json')
		
		# Get all files in $getZimmermanToolsFolderKapeNet6 that match any of the extensions in $fileExts
		$files = Get-ChildItem -Path "$getZimmermanToolsFolderKapeNet6\*" -Include $fileExts
		
		# Copy the files to the destination
		foreach ($file in $files)
		{
			if (Test-Path $file)
			{
				Copy-Item -Path $file -Destination $kapeModulesBin -Recurse -Force
				Log -logFilePath $logFilePath -msg "Copying $file to $kapeModulesBin"
			}
			else
			{
				Log -logFilePath $logFilePath -msg "$file not found."
				Log -logFilePath $logFilePath -msg "If this continues to happen, try deleting $getZimmermanToolsFolderKapeNet6\!!!RemoteFileDetails.csv and re-running this script"
			}
		}
		
		Log -logFilePath $logFilePath -msg "Copied remaining EZ Tools binaries to $kapeModulesBin successfully"
		
		# This removes the downloaded EZ Tools that we no longer need to reside on disk
		Log -logFilePath $logFilePath -msg "Removing extra copies of EZ Tools from $getZimmermanToolsFolderKapeNet6"
		Remove-Item -Path $getZimmermanToolsFolderKapeNet6 -Recurse -Force -ErrorAction SilentlyContinue
	}
	else
	{
		Log -logFilePath $logFilePath -msg "$getZimmermanToolsFolderKapeNet6 doesn't exist. Make sure you have the latest version of Get-ZimmermanTools.ps1 in $kapeModulesBin"
	}
}

function Conclude-Script
{
	[CmdletBinding()]
	param ()
	
	Log -logFilePath $logFilePath -msg ' --- Administrative ---'
	Log -logFilePath $logFilePath -msg 'Thank you for keeping this instance of KAPE updated!'
	Log -logFilePath $logFilePath -msg 'Please be sure to run this script on a regular basis and follow the GitHub repositories associated with KAPE and EZ Tools!'
	Log -logFilePath $logFilePath -msg ' --- GitHub Repositories of Interest ---'
	Log -logFilePath $logFilePath -msg 'KapeFiles (Targets/Modules): https://github.com/EricZimmerman/KapeFiles'
	Log -logFilePath $logFilePath -msg 'RECmd (RECmd Batch Files): https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples'
	Log -logFilePath $logFilePath -msg 'EvtxECmd (EvtxECmd Maps): https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps'
	Log -logFilePath $logFilePath -msg 'SQLECmd (SQLECmd Maps): https://github.com/EricZimmerman/SQLECmd/tree/master/SQLMap/Maps'
	
	$stopwatch.stop()
	
	$Elapsed = $stopwatch.Elapsed.TotalSeconds
	
	Log -logFilePath $logFilePath -msg "Total Processing Time: $Elapsed seconds"
}

# Now that all functions have been declared, let's start executing them in order
try
{
	# Let's get some basic info about the script and output it to the log
	Start-Script
	
	# Let's set up the variables we're going to need for the rest of the script
	Set-Variables
	
	# Lets make sure this script is up to date
	if ($PSBoundParameters.Keys.Contains('DoNotUpdate'))
	{
		Log -logFilePath $logFilePath -msg 'Skipping check for updated $kapeEzToolsAncillaryUpdaterFileName script because -DoNotUpdate parameter set.'
	}
	else
	{
		Get-LatestEZToolsUpdater
	}
	
	# Let's update KAPE first
	& Get-KAPEUpdateEXE
	
	# Let's download Get-ZimmermanTools.zip and extract Get-ZimmermanTools.ps1
	& Get-ZimmermanTools
	
	# Let's move all EZ Tools and place them into .\KAPE\Modules\bin
	Move-EZToolsNET6
	
	# Let's update KAPE, EvtxECmd, RECmd, and SQLECmd's ancillary files
	& Sync-KAPETargetsModules
	& Sync-EvtxECmdMaps
	& Sync-RECmdBatchFiles
	& Sync-SQLECmdMaps
	
	# Let's output our final administrative messages to close out the script
	Conclude-Script
}
catch [System.IO.IOException] {
	# Handle specific IOException related to file operations
	Log -logFilePath $logFilePath -msg "IOException occurred: $($_.Message)"
}
catch [System.Exception] {
	# Handle any other exception that may have occurred
	Log -logFilePath $logFilePath -msg "Exception occurred: $($_.Exception.Message)"
}
finally
{
	# This block will always run, even if there was an exception
	Log -logFilePath $logFilePath -msg ' --- End of session ---'
	
	if (-not $silent)
	{
		Pause
	}
}

# SIG # Begin signature block
# MIIviwYJKoZIhvcNAQcCoIIvfDCCL3gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCNYPRB1izNqnja
# D+Q+0DLuF8g5NBvYbnBU+z/1EIJ3vaCCKJAwggQyMIIDGqADAgECAgEBMA0GCSqG
# SIb3DQEBBQUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQIDBJHcmVhdGVyIE1hbmNo
# ZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoMEUNvbW9kbyBDQSBMaW1p
# dGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2VydmljZXMwHhcNMDQwMTAx
# MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwS
# R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFD
# b21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZp
# Y2VzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkCd9G7h6naHHE1F
# RI6+RsiDBp3BKv4YH47kAvrzq11QihYxC5oG0MVwIs1JLVRjzLZuaEYLU+rLTCTA
# vHJO6vEVrvRUmhIKw3qyM2Di2olV8yJY897cz++DhqKMlE+faPKYkEaEJ8d2v+PM
# NSyLXgdkZYLASLCokflhn3YgUKiRx2a163hiA1bwihoT6jGjHqCZ/Tj29icyWG8H
# 9Wu4+xQrr7eqzNZjX3OM2gWZqDioyxd4NlGs6Z70eDqNzw/ZQuKYDKsvnw4B3u+f
# mUnxLd+sdE0bmLVHxeUp0fmQGMdinL6DxyZ7Poolx8DdneY1aBAgnY/Y3tLDhJwN
# XugvyQIDAQABo4HAMIG9MB0GA1UdDgQWBBSgEQojPpbxB+zirynvgqV/0DCktDAO
# BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zB7BgNVHR8EdDByMDigNqA0
# hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2Vz
# LmNybDA2oDSgMoYwaHR0cDovL2NybC5jb21vZG8ubmV0L0FBQUNlcnRpZmljYXRl
# U2VydmljZXMuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQAIVvwC8Jvo/6T61nvGRIDO
# T8TF9gBYzKa2vBRJaAR26ObuXewCD2DWjVAYTyZOAePmsKXuv7x0VEG//fwSuMdP
# WvSJYAV/YLcFSvP28cK/xLl0hrYtfWvM0vNG3S/G4GrDwzQDLH2W3VrCDqcKmcEF
# i6sML/NcOs9sN1UJh95TQGxY7/y2q2VuBPYb3DzgWhXGntnxWUgwIWUDbOzpIXPs
# mwOh4DetoBUYj/q6As6nLKkQEyzU5QgmqyKXYPiQXnTUoppTvfKpaOCibsLXbLGj
# D56/62jnVvKu8uMrODoJgbVrhde+Le0/GreyY+L1YiyC1GoAQVDxOYOflek2lphu
# MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0BAQwFADB7
# MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
# VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
# AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAwMFoXDTI4
# MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIFJvb3Qg
# UjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIEJHQu/xYj
# ApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7fbu2ir29
# BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGrYbNzszwL
# DO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTHqi0Eq8Nq
# 6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv64IplXCN
# /7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2JmRCxrds+
# LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0POM1nqFOI
# +rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXybGWfv1Vb
# HJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyheBe6QTHrn
# xvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXycuu7D1fkK
# dvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7idFT/+IAx1
# yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQYMBaAFKAR
# CiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJwIDaRXBeF
# 5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggr
# BgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1UdHwQ8MDow
# OKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2Vy
# dmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3SamES4aUa1
# qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+BtlcY2fU
# QBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8ZsBRNraJ
# AlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx2jLsFeSm
# TD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyoXZ3JHFuu
# 2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p1FiAhORF
# e1rYMIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAw
# TDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkds
# b2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcN
# MzQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
# NjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQss
# grRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToV
# Bu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRM
# IRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIf
# KtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfI
# WHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2
# HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH
# 8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+
# 7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfnc
# BZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWz
# jMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bon
# vzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
# BTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAW
# gBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9
# lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3i
# EZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5
# Mr6155wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm
# 8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/h
# pvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEa
# SHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB1
# 0jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TI
# vWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt
# 9x+vJJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEg
# fn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJ
# wGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBAwggYaMIIEAqADAgECAhBiHW0MUgGe
# O5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUg
# U2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTla
# MFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNV
# BAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0GCSqG
# SIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjIztNs
# fvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NVDgFi
# gOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/36F09
# fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05ZwmRmT
# nAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm+qxp
# 4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUedyz8
# rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz44MPZ
# 1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBMdlyh
# 2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaA
# FDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritUpimq
# F6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsGA1Ud
# HwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1Ymxp
# Y0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUF
# BzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2ln
# bmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv
# LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURhw1aV
# cdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0ZdOaWT
# syNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajjcw5+
# w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNcWbWD
# RF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalOhOfC
# ipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJszkye
# iaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z76mKn
# zAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5JKdGv
# spbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHHj95E
# jza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2Bev6
# SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/L9Uo
# 2bC5a4CH2RwwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEB
# DAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAw
# MFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENB
# IC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDw
# AuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PE
# Ne2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39
# eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b
# 7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKW
# O/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZ
# uT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7
# vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9
# bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUln
# EYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKs
# DlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkd
# Zqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYD
# VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2Jh
# bHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIG
# CCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5
# LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG
# +wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5L
# FST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRI
# RVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dI
# ZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5q
# ucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+I
# Lj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI8
# 5Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7
# qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgU
# QGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZ
# HL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjG
# pGqqIpswggZoMIIEUKADAgECAhABSJA9woq8p6EZTQwcV7gpMA0GCSqGSIb3DQEB
# CwUAMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEw
# LwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0
# MB4XDTIyMDQwNjA3NDE1OFoXDTMzMDUwODA3NDE1OFowYzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExOTA3BgNVBAMMMEdsb2JhbHNpZ24g
# VFNBIGZvciBNUyBBdXRoZW50aWNvZGUgQWR2YW5jZWQgLSBHNDCCAaIwDQYJKoZI
# hvcNAQEBBQADggGPADCCAYoCggGBAMLJ3AO2G1D6Kg3onKQh2yinHfWAtRJ0I/5e
# L8MaXZayIBkZUF92IyY1xiHslO+1ojrFkIGbIe8LJ6TjF2Q72pPUVi8811j5bazA
# L5B4I0nA+MGPcBPUa98miFp2e0j34aSm7wsa8yVUD4CeIxISE9Gw9wLjKw3/QD4A
# QkPeGu9M9Iep8p480Abn4mPS60xb3V1YlNPlpTkoqgdediMw/Px/mA3FZW0b1XRF
# OkawohZ13qLCKnB8tna82Ruuul2c9oeVzqqo4rWjsZNuQKWbEIh2Fk40ofye8eEa
# VNHIJFeUdq3Cx+yjo5Z14sYoawIF6Eu5teBSK3gBjCoxLEzoBeVvnw+EJi5obPrL
# TRl8GMH/ahqpy76jdfjpyBiyzN0vQUAgHM+ICxfJsIpDy+Jrk1HxEb5CvPhR8toA
# Ar4IGCgFJ8TcO113KR4Z1EEqZn20UnNcQqWQ043Fo6o3znMBlCQZQkPRlI9Lft3L
# bbwbTnv5qgsiS0mASXAbLU/eNGA+vQIDAQABo4IBnjCCAZowDgYDVR0PAQH/BAQD
# AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBRba3v0cHQIwQ0q
# yO/xxLlA0krG/TBMBgNVHSAERTBDMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMB
# Af8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29j
# c3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAC
# hjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hh
# Mzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1Ud
# HwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEALms+j3+wsGDZ8Z2E3JW2
# 318NvyRR4xoGqlUEy2HB72Vxrgv9lCRXAMfk9gy8GJV9LxlqYDOmvtAIVVYEtuP+
# HrvlEHZUO6tcIV4qNU1Gy6ZMugRAYGAs29P2nd7KMhAMeLC7VsUHS3C8pw+rcryN
# y+vuwUxr2fqYoXQ+6ajIeXx2d0j9z+PwDcHpw5LgBwwTLz9rfzXZ1bfub3xYwPE/
# DBmyAqNJTJwEw/C0l6fgTWolujQWYmbIeLxpc6pfcqI1WB4m678yFKoSeuv0lmt/
# cqzqpzkIMwE2PmEkfhGdER52IlTjQLsuhgx2nmnSxBw9oguMiAQDVN7pGxf+LCue
# 2dZbIjj8ZECGzRd/4amfub+SQahvJmr0DyiwQJGQL062dlC8TSPZf09rkymnbOfQ
# MD6pkx/CUCs5xbL4TSck0f122L75k/SpVArVdljRPJ7qGugkxPs28S9Z05LD7Mtg
# Uh4cRiUI/37Zk64UlaiGigcuVItzTDcVOFBWh/FPrhyPyaFsLwv8uxxvLb2qtuto
# I/DtlCcUY8us9GeKLIHTFBIYAT+Eeq7sR2A/aFiZyUrCoZkVBcKt3qLv16dVfLyE
# G02Uu45KhUTZgT2qoyVVX6RrzTZsAPn/ct5a7P/JoEGWGkBqhZEcr3VjqMtaM7WU
# M36yjQ9zvof8rzpzH3sg23IwggZ1MIIE3aADAgECAhA1nosluv9RC3xO0e22wmkk
# MA0GCSqGSIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBSMzYwHhcNMjIwMTI3MDAwMDAwWhcNMjUwMTI2MjM1OTU5WjBSMQswCQYDVQQG
# EwJVUzERMA8GA1UECAwITWljaGlnYW4xFzAVBgNVBAoMDkFuZHJldyBSYXRoYnVu
# MRcwFQYDVQQDDA5BbmRyZXcgUmF0aGJ1bjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALe0CgT89ev6jRIhHdrp9cdPnRoF5AV3wQdWzNG8JiY4dpN1YVwG
# Llw8aBosm0NIRz2/y/kriL+Jdu/FFakJdpB8l/J+mesliYhN+zj9vFviBjrElMAS
# EBS9DXKaUFuqZMGiC6k6yASGfyqF121OkLZ2JImy4a0C43Pd74dbf+/Ae4QHj66o
# tahUBL++7ayba/TJebhRdEq0wFiaxYsZOt18c3LLfAw0fniHfMBZXXJAQhgu1xfg
# pw7OE4N/M5or5VDVQ4ovtSFDVRzRARIF4ibZZqB76Rp5MuI0pMCs74TPN6WdlzGT
# DBu4pTS064iGx5hlP+GB5s/w/YW1BDigFV6yaERsbet9G2lsMmNwZtI6zUuGd9HE
# td5isz/9ENhLcFoaJE7/KK8CL5jt8i9I3Lx+5EOgEwm65eHm45bq63AVKvSHrjis
# uxX89jWTeslKMM/rpw8GMrNBxo9DZvDS4+kCloFKARiwKHJIKpNWUT3T8Kw6Q/ay
# xUt7TKp+cqh0U9YoXLbXIYMpLa5KfOsf21SqfSrhJ+rSEPEBM11uX41T/mQD5sAr
# N9AIPQxp6X7qLckzClylAQgzF2OVHEEi5m2kmb0lvfMOMGQ3BgwQHCRcd65wugzC
# Iipb5KBTq+HJLgRWFwYGraxcfsLkkwBY1ssKPaVpAgMDmlWJo6hDoYR9AgMBAAGj
# ggHDMIIBvzAfBgNVHSMEGDAWgBQPKssghyi47G9IritUpimqF6TNDDAdBgNVHQ4E
# FgQUUwhn1KEy//RT4cMg1UJfMUX5lBcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
# /wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQMEoG
# A1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8v
# c2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2
# LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2Vj
# dGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsG
# AQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAlBgNVHREEHjAcgRphbmRy
# ZXcuZC5yYXRoYnVuQGdtYWlsLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEATPy2wx+J
# fB71i+UCYCOjFFBqrA4kCxsHv3ihLjF4N3g8jb7A156vBangR3BDPQ6lF0YCPwEF
# E9MQzqG7OgkUauX0vfPeuVe8cEadUFlrmb6xCmXsxKdGXObaITeGABz97AzLKxgx
# Rf7xCEKsAzvbuaK3lvb3Me9jtRVn9Q69sBTE5I/IDf2PoG/tO/ibPYXC1KpilBNT
# 0A28xMtQ1ijTS0dnbOyTMaUBCZUrNR/9qY2sOBhvxuvSouWjuEazDLTCs6zsMBQH
# 9vfrLoNlvEXI5YO9Ck19kT9pZ2rGFO7y8ySRmoVpZvHI29Z4bXBtGUGb2g/RRppi
# d5anuRtN+Skr7S1wdrNlhBIYErmCUPH2RPMphN2wmUy6IsDpdTPJkPTmU83q3tpO
# BGwvyTdxhiPIurZMXSDXfUyGB2iiXoyUHP2caVUmsarEb3BgCEf0PT2rO971WCDn
# G0mMgle2Yur4z3eWEsKUoPdFAoiizb7CddijTOsNvxYNf0XEg5Ek1gTSMYIGUTCC
# Bk0CAQEwaDBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhA1
# nosluv9RC3xO0e22wmkkMA0GCWCGSAFlAwQCAQUAoEwwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwLwYJKoZIhvcNAQkEMSIEINBqCXocJQcjCX9RzdfQr8LsZQMD
# HlnopxVj2ou6ixaBMA0GCSqGSIb3DQEBAQUABIICAKU+w1cvmCUK2+ORPNqZZwXf
# UKuVZI8S4XZc+DF+xrMCTQwi/JX689h32khNY0Jrp+1ewhpH6k4bo8w+DOjGhKP0
# CWFE2LAlnDpuXRgcQJwPUTSaR9fPhGh1nsUCQbWE3+Ter2DOLOrfj3TyGSl8CiHA
# naTxBu0gjL9so0GFBzikUagQcvr0+2aGSe1I8dZoWm/wznmuzft90xfn7Y0ZTPKv
# 67GUXxH6D0vfCl7oj61/WcYkRYrPiHzDAuGXMY92pNBMq2qa+goeHEborEMoLz3Z
# CLtezyF1jLReUN0kKWtT0FNYOC3cvmo1FrcDlXcFhtvZMIa57CG9UBQCj4OT4anK
# XAkhxgd49XHJ2NqxENr2I6Yzw8B7pfpZHx6v/SmzhJaXbIHt0aZBhgMeKCpu8swo
# /jhYkPE3tHZJFI9L22ceeo+x+uuHgtN29tsKAMuYiuycHlwPLkUyrUy/hdDxv7Fe
# +lnHVa92T9Fp/VFWDGtmCPNJ4U6hdTAvfmfkgVFSe86129qssvnvuBsokFmoW7j7
# P90+Jjy+7sNctKiHMuKuMFmFUN8ens8JWP8PJbojmlFOhhU5qx7PSyNLiT3Vsqsk
# FMa+4psEmBMIXih/zgmZd1mGxGCi1/nkAOJRTYPpYymhUgRKN4LwZEgT56L3FAV9
# bcUl/DufsZIcpQmiaJXqoYIDbDCCA2gGCSqGSIb3DQEJBjGCA1kwggNVAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAFI
# kD3CirynoRlNDBxXuCkwCwYJYIZIAWUDBAIBoIIBPTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA4MDQxNDU2MDdaMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJ
# BDEiBCCfRhp5GNFKNvxisCSaA7R3zO43W2mo+run373Q2Npx7TCBpAYLKoZIhvcN
# AQkQAgwxgZQwgZEwgY4wgYsEFDEDDhdqpFkuqyyLregymfy1WF3PMHMwX6RdMFsx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQD
# EyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABSJA9
# woq8p6EZTQwcV7gpMA0GCSqGSIb3DQEBCwUABIIBgBKz4b88unpd7AXWa1J9PUoo
# jiSndkcHoKntOJCIcY1CYzPlBnmFVi4CqehsYRqOBy1+h8AsMcUW1DZBAwER5XXI
# qp00lBZvzPJRg3c4hpmlQ7cJ6Byj9vTqQsTmQjIHzjqLa67DaHDu2/+suiVZEvWr
# hhmisJ7i7Mh5DPPyEwCes1ukOIuEaSDbOIIiTvnSZSiT4304r+6zDkWHIk0kg2Fc
# xIcN17zrUHLcPfTCXDfeLiTSg7s9nYZA43/v/sazgOUsJLMWxYtZ2cRfPEXwbbDA
# 4AUxEjDe+frMuCEL0ACLf64N+5aMDYr8ObQaIewK/HaKjARajbswGsgWhz/ekUra
# VACthO4p8a0SRB7WeIheAgnXSFu2EY7DJz3m1snQdS9GVoAP7ZFped5n4xp3dB7t
# h4xxj5+iROUuK4F9TzJkBWQ7U4vZus8/Zhtd4k00ZNRPJI/25pRU/ysMsjIOQ5F5
# HNRyx8TkZxD0TjLQEGFRy14ovjh5Q/pfN99ka37+aQ==
# SIG # End signature block
