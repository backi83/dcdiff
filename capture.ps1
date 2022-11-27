#
# dcdiff capture module v0.5
#
# Author: MB
#
#
#
#
#############################
# CHANGELOG
#############################
# v0.6 (22.11.2022)
# names changed for clarity 
#
#
#
# v0.5 (23.08.2022)
# added comments
#
#############################
# REQUIREMENTS
#############################
#
#nothing special
#see compare-module for its requirements



$name=$null
$targetfolder=$null

#user input name
$namePattern = "^[a-zA-Z0-9]+$"
while ($name -eq $null){
	$name = read-host "Enter name to identify later"
	if (-not($name -match $namePattern)){
		Write-host "Invalid name. a-zA-Z0-9"
		$name = $null
	}
}
#user input directory
while ($targetfolder -eq $null){
	$targetfolder = read-host "Enter existing target directory name or leave blank to use current"
	if ([string]::IsNullOrEmpty($targetfolder)) {
		$targetfolder = $PSScriptRoot
	}
	if (-not(test-path $targetfolder)){
		Write-host "Invalid directory path, re-enter."
		$targetfolder = $null
	}
	elseif (-not (get-item $targetfolder).psiscontainer){
		Write-host "Target must be a directory, re-enter."
		$targetfolder = $null
	}
}

#create folders for base/final files
$baseFolder = Join-Path $targetfolder $name"Base"

if (Test-Path $baseFolder -PathType Container) {
	#Exists 
	Write-host "Folder already exists. Delete first or choose different name";
	exit
}
New-Item -Path $baseFolder -ItemType Directory -Force | out-null

$finalFolder = Join-Path $targetfolder $name"Final"

if (Test-Path $finalFolder -PathType Container) {
	#Exists 
	Write-host "Folder already exists. Delete first or choose different name";
	exit
}
New-Item -Path $finalFolder -ItemType Directory -Force | out-null

#wait for user input
Write-host "Press any key to capture base-state";

$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-host "Please wait"

#CAPTURE BASELINE STUFF
#NTDS
Restart-Service -Name NTDS -force
$ntdsTarget = Join-Path $baseFolder ntds.dit
esentutl /y c:\Windows\NTDS\NTDS.dit /vssrec edb . /d $ntdsTarget
#UAL by METHOD ESENTUTL
#disabled because state of resulting db is not recent
#$ualTarget = Join-Path $baseFolder current_esentutl.mdb
#esentutl /y c:\Windows\System32\LogFiles\Sum\Current.mdb /vssrec Svc . /d $ualTarget
#UAL by METHOD STOPSVC - more reliable
$ualTarget = Join-Path $baseFolder current_stopsvc.mdb
stop-service ualsvc
#copy file to baseline folder
Copy-Item -Path C:\Windows\System32\LogFiles\Sum\Current.mdb -Destination $ualTarget
start-service ualsvc
#create baseline shadow copy
$vscResult = vssadmin create shadow /for=c:
#read number from output and save to file
$vscTarget = Join-Path $baseFolder vscNo.dcdif
$vscPathNo = Select-String -InputObject $vscResult -Pattern "(?<=HarddiskVolumeShadowCopy)\d{1,}($)" -AllMatches | % {$_.Matches.Groups[0].Value}
$vscPathNo > $vscTarget
#wait 5 seconds to get distance to previous actions
Start-Sleep -Seconds 5
#record start time
$starttime = (Get-Date).ToString("yyyyMMddHHmmss")
#wait for user input
Write-host "Begin! Afterwards press any key to capture final-state"
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-host "Please wait"


#CAPTURE FINAL STUFF
#create final shadow copy
$vscResult = vssadmin create shadow /for=c:
#read number from output and save to file
$vscTarget = Join-Path $finalFolder vscNo.dcdif
$vscPathNo = Select-String -InputObject $vscResult -Pattern "(?<=HarddiskVolumeShadowCopy)\d{1,}($)" -AllMatches | % {$_.Matches.Groups[0].Value}
$vscPathNo > $vscTarget
#NTDS
Restart-Service -Name NTDS -force
$ntdsTarget = Join-Path $finalFolder ntds.dit
esentutl /y c:\Windows\NTDS\NTDS.dit /vssrec edb . /d $ntdsTarget
#UAL by METHOD ESENTUTL
#disabled because state of resulting db is not recent
#$ualTarget = Join-Path $finalFolder current_esentutl.mdb
#esentutl /y c:\Windows\System32\LogFiles\Sum\Current.mdb /vssrec Svc . /d $ualTarget
#UAL by METHOD STOPSVC
$ualTarget = Join-Path $finalFolder current_stopsvc.mdb
stop-service ualsvc
#copy file to final folder
Copy-Item -Path C:\Windows\System32\LogFiles\Sum\Current.mdb -Destination $ualTarget
start-service ualsvc

#write start/endtime to files
$startTimeTarget = Join-Path $baseFolder starttime.dcdif
$starttime | out-file $startTimeTarget
$endTimeTarget = Join-Path $finalFolder endtime.dcdif
#record end time
$endtime = (Get-Date).ToString("yyyyMMddHHmmss")
$endtime | out-file $endTimeTarget

Write-host "Done."
#ask to proceed with compare module
$choices  = '&Yes', '&No'
$proceed = $Host.UI.PromptForChoice("Proceed", "Do you want to proceed with comparison?", $choices, 1)
if ($proceed -ne 0) {
    Write-Host 'Cancelled'
} else {
    & .\compare.ps1 $name $targetfolder
}
