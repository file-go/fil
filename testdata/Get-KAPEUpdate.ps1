<#
    .SYNOPSIS
    Ths script will download KAPE and extract it to the current working directory. It is expected this script is run from an existing KAPE directory.
    .DESCRIPTION
    This script will attempt to determine what version is on the local system based on the kape.exe binary
    .EXAMPLE
    C:\PS> Get-KAPEUpdate.ps1 
    
    .NOTES
    Author: Eric Zimmerman
    Date:   January 22, 2019    
#>

function Write-Color {
    <#
	.SYNOPSIS
        Write-Color is a wrapper around Write-Host.
        It provides:
        - Easy manipulation of colors,
        - Logging output to file (log)
        - Nice formatting options out of the box.
	.DESCRIPTION
        Author: przemyslaw.klys at evotec.pl
        Project website: https://evotec.xyz/hub/scripts/write-color-ps1/
        Project support: https://github.com/EvotecIT/PSWriteColor
        Original idea: Josh (https://stackoverflow.com/users/81769/josh)
	.EXAMPLE
    Write-Color -Text "Red ", "Green ", "Yellow " -Color Red,Green,Yellow
    .EXAMPLE
	Write-Color -Text "This is text in Green ",
					"followed by red ",
					"and then we have Magenta... ",
					"isn't it fun? ",
					"Here goes DarkCyan" -Color Green,Red,Magenta,White,DarkCyan
    .EXAMPLE
	Write-Color -Text "This is text in Green ",
					"followed by red ",
					"and then we have Magenta... ",
					"isn't it fun? ",
                    "Here goes DarkCyan" -Color Green,Red,Magenta,White,DarkCyan -StartTab 3 -LinesBefore 1 -LinesAfter 1
    .EXAMPLE
	Write-Color "1. ", "Option 1" -Color Yellow, Green
	Write-Color "2. ", "Option 2" -Color Yellow, Green
	Write-Color "3. ", "Option 3" -Color Yellow, Green
	Write-Color "4. ", "Option 4" -Color Yellow, Green
	Write-Color "9. ", "Press 9 to exit" -Color Yellow, Gray -LinesBefore 1
    .EXAMPLE
	Write-Color -LinesBefore 2 -Text "This little ","message is ", "written to log ", "file as well." `
				-Color Yellow, White, Green, Red, Red -LogFile "C:\testing.txt" -TimeFormat "yyyy-MM-dd HH:mm:ss"
	Write-Color -Text "This can get ","handy if ", "want to display things, and log actions to file ", "at the same time." `
				-Color Yellow, White, Green, Red, Red -LogFile "C:\testing.txt"
    .EXAMPLE
    # Added in 0.5
    Write-Color -T "My text", " is ", "all colorful" -C Yellow, Red, Green -B Green, Green, Yellow
    wc -t "my text" -c yellow -b green
    wc -text "my text" -c red
    .NOTES
        CHANGELOG
        Version 0.5 (25th April 2018)
        -----------
        - Added backgroundcolor
        - Added aliases T/B/C to shorter code
        - Added alias to function (can be used with "WC")
        - Fixes to module publishing
        Version 0.4.0-0.4.9 (25th April 2018)
        -------------------
        - Published as module
        - Fixed small issues
        Version 0.31 (20th April 2018)
        ------------
        - Added Try/Catch for Write-Output (might need some additional work)
        - Small change to parameters
        Version 0.3 (9th April 2018)
        -----------
        - Added -ShowTime
        - Added -NoNewLine
        - Added function description
        - Changed some formatting
        Version 0.2
        -----------
        - Added logging to file
        Version 0.1
        -----------
        - First draft
        Additional Notes:
        - TimeFormat https://msdn.microsoft.com/en-us/library/8kb3ddd4.aspx
    #>
    [alias('Write-Colour')]
    [CmdletBinding()]
    param (
        [alias ('T')] [String[]]$Text,
        [alias ('C', 'ForegroundColor', 'FGC')] [ConsoleColor[]]$Color = [ConsoleColor]::White,
        [alias ('B', 'BGC')] [ConsoleColor[]]$BackGroundColor = $null,
        [alias ('Indent')][int] $StartTab = 0,
        [int] $LinesBefore = 0,
        [int] $LinesAfter = 0,
        [int] $StartSpaces = 0,
        [alias ('L')] [string] $LogFile = '',
        [Alias('DateFormat', 'TimeFormat')][string] $DateTimeFormat = 'yyyy-MM-dd HH:mm:ss',
        [alias ('LogTimeStamp')][bool] $LogTime = $true,
        [ValidateSet('unknown', 'string', 'unicode', 'bigendianunicode', 'utf8', 'utf7', 'utf32', 'ascii', 'default', 'oem')][string]$Encoding = 'Unicode',
        [switch] $ShowTime,
        [switch] $NoNewLine
    )
    $DefaultColor = $Color[0]
    if ($null -ne $BackGroundColor -and $BackGroundColor.Count -ne $Color.Count) { Write-Error "Colors, BackGroundColors parameters count doesn't match. Terminated." ; return }
    #if ($Text.Count -eq 0) { return }
    if ($LinesBefore -ne 0) {  for ($i = 0; $i -lt $LinesBefore; $i++) { Write-Host -Object "`n" -NoNewline } } # Add empty line before
    if ($StartTab -ne 0) {  for ($i = 0; $i -lt $StartTab; $i++) { Write-Host -Object "`t" -NoNewLine } }  # Add TABS before text
    if ($StartSpaces -ne 0) {  for ($i = 0; $i -lt $StartSpaces; $i++) { Write-Host -Object ' ' -NoNewLine } }  # Add SPACES before text
    if ($ShowTime) { Write-Host -Object "[$([datetime]::Now.ToString($DateTimeFormat))]" -NoNewline} # Add Time before output
    if ($Text.Count -ne 0) {
        if ($Color.Count -ge $Text.Count) {
            # the real deal coloring
            if ($null -eq $BackGroundColor) {
                for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
            } else {
                for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $Color[$i] -BackgroundColor $BackGroundColor[$i] -NoNewLine }
            }
        } else {
            if ($null -eq $BackGroundColor) {
                for ($i = 0; $i -lt $Color.Length ; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
                for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $DefaultColor -NoNewLine }
            } else {
                for ($i = 0; $i -lt $Color.Length ; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $Color[$i] -BackgroundColor $BackGroundColor[$i] -NoNewLine }
                for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host -Object $Text[$i] -ForegroundColor $DefaultColor -BackgroundColor $BackGroundColor[0] -NoNewLine }
            }
        }
    }
    if ($NoNewLine -eq $true) { Write-Host -NoNewline } else { Write-Host } # Support for no new line
    if ($LinesAfter -ne 0) {  for ($i = 0; $i -lt $LinesAfter; $i++) { Write-Host -Object "`n" -NoNewline } }  # Add empty line after
    if ($Text.Count -ne 0 -and $LogFile -ne "") {
        # Save to file
        $TextToFile = ""
        for ($i = 0; $i -lt $Text.Length; $i++) {
            $TextToFile += $Text[$i]
        }
        try {
            if ($LogTime) {
                Write-Output -InputObject "[$([datetime]::Now.ToString($DateTimeFormat))]$TextToFile" | Out-File -FilePath $LogFile -Encoding $Encoding -Append
            } else {
                Write-Output -InputObject "$TextToFile" | Out-File -FilePath $LogFile -Encoding $Encoding -Append
            }
        } catch {
            $_.Exception
        }
    }
}

$TestColor = (Get-Host).ui.rawui.ForegroundColor
if ($TestColor -eq -1) 
{
    $defaultColor = [ConsoleColor]::Gray
} else {
    $defaultColor = $TestColor
}

write-host ""
Write-Host "Ths script will download KAPE and extract it to the current working directory." -BackgroundColor Blue
Write-Host "It is expected this script is run from an existing KAPE directory." -BackgroundColor Blue
write-host ""

$currentDirectory = Resolve-Path -Path ('.')

$kapePath = Join-Path -Path $currentDirectory -ChildPath 'kape.exe'

if (Test-Path -Path $kapePath)
{
  while ((get-process -Name "*kape").count -ne 0)
  {
    write-color -Text "* ", "KAPE appears to be running!. Close all running instances of kape.exe or gkape.exe!" -Color Green,Red

    write-host ""
    Write-Host 'Press any key to check again...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
  }

    write-color -Text "* ", "Found kape.exe binary." -Color Green,$defaultColor

    $localVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($kapePath).FileVersion


write-color -Text "* ", "Local version is '$localVersion'`n" -Color Green,$defaultColor
    
write-color -Text "* ", "Checking server for current version..." -Color Green,$defaultColor
    
    $serverResponse = Invoke-WebRequest -Uri 'https://s3.amazonaws.com/cyb-us-prd-kape/ver.txt' -UseBasicParsing 
    $content = $serverResponse.Content
    
write-color -Text "* ", "Server version is '$content'" -Color Green,$defaultColor
    
    $localVerNoDot = $localVersion.Replace('.','')
    $serverVerNoDot = $content.Replace('.','')
    
    [int]$localInt = [convert]::ToInt32($localVerNoDot)
    [int]$serverInt = [convert]::ToInt32($serverVerNoDot)
    
    if ($serverInt -gt $localInt)
    {

      write-color -Text "* ", "A new version is available! Downloading..." -Color Green,$defaultColor
      
      $destFile = Join-Path -Path $currentDirectory -ChildPath 'kape.zip'
      
      $dUrl = 'https://bit.ly/2Ei31Ga'
      
      $progressPreference = 'silentlyContinue'
            
      Invoke-WebRequest -Uri $dUrl -OutFile $destFile -ErrorAction:Stop -UseBasicParsing
      
      $progressPreference = 'Continue'
      
	write-color -Text "* ", "Unzipping new version..." -Color Green,$defaultColor

      Expand-Archive -Path $destFile -DestinationPath $currentDirectory -Force
      
      $kapeDir = Join-Path -Path $currentDirectory -ChildPath "KAPE"

      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "Documentation") -Destination $currentDirectory -Force -Recurse
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "Targets") -Destination $currentDirectory -Force -Recurse
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "Modules") -Destination $currentDirectory -Force -Recurse
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "ChangeLog.txt") -Destination $currentDirectory -Force 
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "Get-KAPEUpdate.ps1") -Destination $currentDirectory -Force 
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "gkape.exe") -Destination $currentDirectory -Force 
      Copy-Item -Path (Join-Path -Path $kapeDir -ChildPath "kape.exe") -Destination $currentDirectory -Force 
      
      $localVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($kapePath).FileVersion
	write-color -Text "* ", "Local version is now '$localVersion'!" -Color Green,$defaultColor

      Write-Host ""      
	write-color -Text "* ", "Change log (newest 20 lines)" -Color Green,$defaultColor
      
      Get-Content -Path (Join-Path  -Path $currentDirectory -ChildPath 'ChangeLog.txt') -TotalCount 20
            
      remove-item -Path $destFile
      remove-item -Path (Join-Path -Path $currentDirectory -ChildPath 'KAPE') -Recurse

	write-host ""
	write-host ""

	write-color -Text "* ", "Be sure to update local Target and Module configurations!" -Color Green,Red
	write-color -Text "* ", "This can be done via gkape (click Sync button) or run 'kape.exe --sync' from the command line" -Color Green,$defaultColor

	write-host ""
    }
    else
    {
	Write-Host ""
	write-color -Text "* ", "Local and server version are the same. No update available" -Color Green,$defaultColor
	Write-Host ""
    }
}
else
{
	Write-Host ""
	write-color -Text "* ", "kape.exe not found in $currentDirectory! Nothing to do" -Color Green,$defaultColor
	Write-Host ""
}



# SIG # Begin signature block
# MIINKAYJKoZIhvcNAQcCoIINGTCCDRUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4llGb4WuKal9nDS0zMv7cgSa
# ax2gggpqMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFMjCC
# BBqgAwIBAgIQBIqzU5QLpYluNuUV0AgAmDANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTIwMDQwODAwMDAwMFoXDTIzMDcwNzEyMDAwMFowbzEL
# MAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMREwDwYDVQQHEwhOZXcgWW9y
# azEcMBoGA1UECgwTRHVmZiAmIFBoZWxwcywgTExDLjEcMBoGA1UEAwwTRHVmZiAm
# IFBoZWxwcywgTExDLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKtT
# k9DHu/SFN5xtY2piB3yH/yU4BkfQf9Ekd6kdC3oK/CI00N5TukcO1WOrv+re9t5+
# jqZAKnqLZQLpw3Qz8GFT0RTwN6r7kx1IXq7epy/mm8uod7KOFzpet/b1rUur1uvl
# FX/7KudXA4q9PAltmATfyY3wnxnT+KNoVR8P5EyPQw5Yi8jX47RekhEZp/FJpsJ3
# KvDTptPzqTwkmEiDrwMoTkwI/HQRx+N8t57djusHCdFwz0xPXX4A3XbPtdv3ZeYP
# a8tP8tlRbag2FDl78qXAKO/4HmcUpDFO17ENeiHVTaDDHHvzdQrKgt/0Yh5iCnYP
# yyC1ohulK+ZmMHoYMhcCAwEAAaOCAcUwggHBMB8GA1UdIwQYMBaAFFrEuXsqCqOl
# 6nEDwGD5LfZldQ5YMB0GA1UdDgQWBBSFlcfBs1o8UNLhv4fge6E2O9erqTAOBgNV
# HQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1oDOg
# MYYvaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5j
# cmwwNaAzoDGGL2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQt
# Y3MtZzEuY3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEW
# HGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGEBggrBgEF
# BQcBAQR4MHYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBO
# BggrBgEFBQcwAoZCaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# U0hBMkFzc3VyZWRJRENvZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJ
# KoZIhvcNAQELBQADggEBAEuYl+raSa+v7O3fwBW54vuJwICasM3hnO34mp2dPorR
# 3XdcpCOMXbQBe8af0q9NMLzUi51i9bfPdDj1MpA1puQ/Wk9CimNsyWLDLm3maBe4
# 1AGwwPeTViks1JFtN/Eseyzab68d6gGf9fGeM9wkmto4DuxlQkHEOKcaUFsqQSJy
# 7WH/X+38VfMTeF5DwSuRgYg3BqkjypuUoZQtf4QvGz75Tm3ycyGBMLUvkwce76tL
# 7JkEUA+6jczFM1prASHEjtQdk6XWAlwkCm5KDXdj329jDO7phtFcENkfKyM4ah5G
# gmxy3AhwF2fc5oedWCh4JHz1UkX4KlRdpKagpyfmZgMxggIoMIICJAIBATCBhjBy
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQg
# SUQgQ29kZSBTaWduaW5nIENBAhAEirNTlAuliW425RXQCACYMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBSX/VhjbK60/ykTsYi1/BMyAZqL5DANBgkqhkiG9w0BAQEFAASCAQBSDWp2
# 3I1l7G0xP0K18+NqFznjaye0R7+1tVOQdyb5n6KnRpc2qX+xgsgaX8nk0aNQ/reC
# nlAXim7BkiOGoMNAvJPNzZg8fYo63NE0qRWflli7DCWzVvfMN+LmXtC2vYrS1Wsn
# GHDZk6cAVHRYLaHPoIKjPobePICR7mxRfpShtBnlJKcwV95hxyFTJEqOG1Bf8XVK
# rdt3MlGUDzdWmq4Bj8kxTqzxCqlt0CTaKPXwKMqL87nBH6XbRWgifOQtBSRDYMV9
# QMk8zOdoPuvqiZiywSjTkhBbGLAOwdXn0ueA8jo1iNBRp6x/qk9so2VSVCV594xc
# VTrDIFDV9KmXpile
# SIG # End signature block
