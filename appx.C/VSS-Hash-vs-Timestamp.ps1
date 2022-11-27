#vssadmin create shadow /for=C:
#remember HKLM\Current..\Control\BackupRestore\FilesNotToBackup
#mklink /d c:\base \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
#PsExec64.exe -i -s powershell.exe #for system level rights

Start-Transcript -Path .\log.txt
$global:failedDate=0
$global:unchangedDate=0
$global:changedDate=0
$global:failed=0
$global:unchanged=0
$global:changed=0
$global:new=0
$global:allfiles=0
$global:deleted=0
$vscBaseFolder = "C:\base"
$vscFinalFolder = "C:\final"

#files to check (all will take long)

#$fileChangesPathes = @("Windows\","Users\","PerfLogs\","ProgramData\","Program Files\","Program Files (x86)\","Recovery\","Config.Msi\","System Volume Information\") #
$fileChangesPathes = @("")


Get-Date
function hasChangedByDate(){
 param (
   $fileBase,
   $fileFinal
 )
	try{
		
		$lastModifiedDateFinal = (Get-Item $fileFinal -force -errorAction stop).LastWriteTime 
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		Write-Host 'DATE: Not Found '$fileFinal #$Error[0].Exception.GetType().FullName
		$global:failedDate++
		return
	}
	catch [System.UnauthorizedAccessException] {
		Write-Host 'DATE: Unauthorized '$fileFinal #$Error[0]
		$global:failedDate++
		return
	}
	catch [System.IO.IOException] {
		Write-Host 'DATE: IOException '$fileFinal #$Error[0]
		$global:failedDate++
		return
	}
	catch {
		Write-Host 'DATE: Any error '$fileFinal #$Error[0]
		$global:failedDate++
		return
	}
	try{
		$lastModifiedDate = (Get-Item $fileBase -force -errorAction stop).LastWriteTime
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		#$global:new++  wont reach, function wont be called in this case

	}
	catch [System.UnauthorizedAccessException] {
		Write-Host 'DATE: Final ok, but base is: Unauthorized '$fileBase #$Error[0]
		$global:failedDate++
		return
	}
	catch [System.IO.IOException] {
		Write-Host 'DATE: Final ok, but base is: IOException '$fileBase #$Error[0]
		$global:failedDate++
		return
	}
	catch {
		Write-Host 'DATE: Final ok, but base is Any error '$fileBase #$Error[0]
		$global:failedDate++
		return
	}
	if($lastModifiedDateFinal -gt $lastModifiedDate){
		#Copy-Item -Path $fileFinal -Destination $global:targetFolderName # -errorAction stop
		#$global:copied += $fileFinal
		"DATE CHANGED: " + $fileFinal | Write-Host
		$global:changedDate++

	}
	else {
		$global:unchangedDate++
	}


}
function getContentMD5(){
 param (
   $file
 )
	try {
		[byte[]]$array = Get-Content -Path $file -Encoding Byte -ReadCount 0 -erroraction stop
		$md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
		$ResultHash = $md5.ComputeHash($array)
		$hexString = ($ResultHash|ForEach-Object ToString X2) -join ''
		return $hexString
	}
	catch {
		throw "Get-Content failed"
	}
}
#for any reason, for some files Get-FileHash fails, but Get-Content works. So this alternative reads file contents and generates an hash by its own. thus, sometimes this fails anyway.
function hasChangedAlternative(){
 param (
   $fileBase,
   $fileFinal
 )
	try{
		
		$FileHashFinal = getContentMD5 $fileFinal
	}
	catch {
		Write-Host 'Alternative failed, Any error '$fileFinal #$Error[0]
		$global:failed++
		return
	}

	try{
		$FileHashBase = getContentMD5 $fileBase
	}
	catch {
		Write-Host 'Alternative failed, Final ok, but Base is Any error '$fileBase #$Error[0]
		$global:failed++
		return
	}
	if ($FileHashFinal -eq $FileHashBase) {
		$global:unchanged++
		"ALT UNCHANGED" + $fileFinal | Write-Host
	}
	else {
		#Copy-Item -Path $fileFinal -Destination $global:targetFolderName # -errorAction stop
		$global:copied += $fileFinal
		"ALT CHANGED: " + $fileFinal | Write-Host
		$global:changed++
	}
}
function hasChangedByHash(){
 param (
   $fileBase,
   $fileFinal
 )
	try{
		
		$FileHashFinal = Get-FileHash $fileFinal -Algorithm MD5 -errorAction stop
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		Write-Host 'Not Found '$fileFinal #$Error[0].Exception.GetType().FullName
		hasChangedAlternative $fileBase $fileFinal # $global:failed++
		return
	}
	catch [System.UnauthorizedAccessException] {
		Write-Host 'Unauthorized '$fileFinal #$Error[0]
		hasChangedAlternative $fileBase $fileFinal #$global:failed++
		return
	}
	catch [System.IO.IOException] {
		Write-Host 'IOException '$fileFinal #$Error[0]
		hasChangedAlternative $fileBase $fileFinal
		#$global:failed++
		return
	}
	catch {
		Write-Host 'Any error '$fileFinal #$Error[0]
		hasChangedAlternative $fileBase $fileFinal
		#$global:failed++
		return
	}
	
	#when final doesnt exists or is unavailable the file can be skipped
	#when we come to this point, the final file is accessible
	
	try{
		$FileHashBase = Get-FileHash $fileBase -Algorithm MD5 -errorAction stop
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		#$global:new++ wont reach, function wont be called in this case

	}
	catch [System.UnauthorizedAccessException] {
		Write-Host 'Final ok, but Base is: Unauthorized '$fileBase #$Error[0]
		#$global:failed++
		hasChangedAlternative $fileBase $fileFinal
		return
	}
	catch [System.IO.IOException] {
		Write-Host 'Final ok, but Base is: IOException '$fileBase #$Error[0]
		hasChangedAlternative $fileBase $fileFinal
		#$global:failed++
		return
	}
	catch {
		Write-Host 'Final ok, but Base is Any error '$fileBase #$Error[0]
		hasChangedAlternative $fileBase $fileFinal
		#$global:failed++
		return
	}
	if ($FileHashFinal.Hash -eq $FileHashBase.Hash) {
		$global:unchanged++
	}
	else {
		#Copy-Item -Path $fileFinal -Destination $global:targetFolderName # -errorAction stop
		$global:copied += $fileFinal
		"CHANGED: " + $fileFinal | Write-Host
		$global:changed++
	}
}



$childsBasePathes = @()
foreach ($path in $fileChangesPathes){
	$path = Join-Path $vscBaseFolder $path
	$childsBasePathes += $path
}


$childsFinalPathes = @()
foreach ($path in $fileChangesPathes){
	$path = Join-Path $vscFinalFolder $path
	$childsFinalPathes += $path
}


$childsBase = Get-ChildItem -Path $childsBasePathes -Recurse -Force -ErrorVariable FailedItemsBase -ErrorAction SilentlyContinue -Attributes !Directory+!ReparsePoint
$childsFinal = Get-ChildItem -Path $childsFinalPathes -Recurse -Force -ErrorVariable FailedItemsFinal -ErrorAction SilentlyContinue -Attributes !Directory+!ReparsePoint # -ErrorVariable FailedItemsBase -ErrorAction SilentlyContinue


$changedEvtxFiles = New-Object System.Collections.Generic.List[System.Object]
$newEvtxFiles = New-Object System.Collections.Generic.List[System.Object]
$filesAmountBase = ( $childsBase | Measure-Object ).Count
$filesAmountFinal = ( $childsFinal | Measure-Object ).Count

$filesAmount = $filesAmountFinal
Write-Host 'Base:'$filesAmountBase
Write-Host 'Final:'$filesAmountFinal


$filesProgress = 0
$childsFinal | Foreach-Object { 
	$global:allfiles++
	$supposedMatchingBaseFile = $_.FullName.replace("final","base")

	if ( (!(Test-Path $supposedMatchingBaseFile -PathType Leaf)) -AND (Test-Path $_.FullName -PathType Leaf)) { # 
		$relativePath = $_.FullName -split "final" 
		"NEW FILE: " + $_.FullName + "test failed:" + $supposedMatchingBaseFile | Write-Host #$relativePath[1]
		$global:new++
	
	}
	else {
		hasChangedByHash $supposedMatchingBaseFile $_.FullName 
		#hasChangedByDate $supposedMatchingBaseFile $_.FullName 
	}
	$filesProgress++
	$percent = [math]::Round($filesProgress * 100 / $filesAmount,2)
	Write-Progress -Activity "Searching changed files" -Status "$percent% of total $filesAmount files done" -PercentComplete $percent
}

$childsBase | 
	Foreach-Object {
		#find files not in post
		$supposedMatchingFinalFile = $_.FullName.replace("base","final")
		if ((!(Test-Path $supposedMatchingFinalFile -PathType Leaf)) -AND (Test-Path $_.FullName -PathType Leaf)) { # 
			#$relativePath = $_.FullName -split "base"
			"DELETED: " + $_.FullName + "test failed:" +$supposedMatchingFinalFile | Write-Host #$relativePath[1]
			$global:deleted++
		}

	}


Write-Host 'Changed compare: '$global:changed
Write-Host 'unchanged compare: '$global:unchanged
Write-Host 'Failed compare: '$global:failed



Write-Host 'Date Changed compare: '$global:changedDate
Write-Host 'Date unchanged compare: '$global:unchangedDate
Write-Host 'Date Failed compare: '$global:failedDate


Write-Host 'New: '$global:new
Write-Host 'deleted:'$global:deleted
Write-Host 'All in post (new+changed+unchanged+failed):'$global:allfiles

Get-Date
Stop-Transcript
