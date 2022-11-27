#
# dcdiff compare module v0.5
#
# Author: MB
#
#
#
#
# TODO
# add ETL file decode (Get-WinEvent -Path "C:\nachher\Windows\System32\LogFiles\WMI\ntfslog.etl" -oldest)
# add registry decode
#
#############################
# CHANGELOG
#############################
# v0.6 (22.11.2022)
# names changed for clarity 
#
#
# v0.5 (23.08.2022)
# added comments
#
# <v0.5
# removed failure in vss compare regarding detecting deleted files. 
# changed compareByHash to throw errors in file log too
# fixed bad design in $supposedMatchingBase/FinalFile.replace 


#############################
# REQUIREMENTS
#############################
# dcdiff-dependencies:
# dcdiff_NtdsAttIds.ps1
# dcdiff_reporttemplate.html
#
# External dependencies:
# Python 3.x (tested with 3.10)
# d/l & build libesedb from https://github.com/libyal/libesedb (esedbexport.exe need to be in $PATH) 
# Kstrike.py from https://raw.githubusercontent.com/backi83/KStrike/ (requires Python 3.x)
# csv-diff (pip install csv-diff)


#############################
# CONFIGURATION
#############################
#fileChangesPathes = pathes to scan for changes
#default is @("Windows\System32\winevt\")
#examples:
#EVTX: Windows\System32\winevt\
#REGISTRY: Windows\System32\config\
#$fileChangesPathes = @("Windows\System32\winevt\","Windows\System32\config\","Users\")
$fileChangesPathes = @("Windows\System32\winevt\")

#DEBUG
$debug=$True #more output in log


#############################
# CONSTANTS
#############################
$logfileName = "log.txt"
$timelineFilename = "timeline.csv"
$timelineFilenameHtml = "timeline.html"
$ntdsReportFilename = "ntdsReport.html"
$ualReportFilename = "ualReport.html"
$filesReportFilename = "filesReport.html"
$mainReportFilename = "report.html"
$mainReportTemplateFilename = "dcdiff_reporttemplate.html"

#############################
# PREREQUISITES
#############################
$name=$args[0]
$targetfolder=$args[1]

if ((Get-Command "esedbexport.exe" -ErrorAction SilentlyContinue) -eq $null ) 
{ 
   Write-Host "Unable to find esedbexport.exe. It must be available in PATH. E.g. copy to C:\Windows\ or add its current path to PATH. Don't forget the libesedb.dll."
   exit
}
#NTDS Attribute Lookup Table
if ( (! (Test-Path ".\dcdiff_NtdsAttIds.ps1" -PathType Leaf))) {
   Write-Host "Unable to find dcdiff_NtdsAttIds.ps1 in current path. Start dcdiff from its root directory."
   exit
}
else {
	. ".\dcdiff_NtdsAttIds.ps1"
}

$dateAttributes = @{
    ATT_LAST_LOGON = 'windowsfiletime' #ATTq589876
	ATT_PWD_LAST_SET = 'windowsfiletime' #ATTq589920
	ATT_BAD_PASSWORD_TIME = 'windowsfiletime' #ATTq589873
	ATT_LAST_LOGON_TIMESTAMP = 'windowsfiletime' #ATTq591520
	ATT_WHEN_CREATED = 'windowstruncatedft' #ATTl131074
	ATT_WHEN_CHANGED = 'windowstruncatedft' #ATTl131075
	time_col = 'windowstruncatedft'
}
#############################
# FUNCTIONS
#############################
#converts windows timestamps to human readable strings
#params:
#func:String = windowsfiletime or windowstruncatedft
#value:Int64 = timestamp
#returns: DateTime in local timezone if given value > 0 otherwise 0
function NTDStoDate(){
	param (
		$func,
		$value
	)

	$valueTrimmed = $value.Trim('"') 
	switch ( $func ) {
		'windowsfiletime' { #100th nanoseconds since 1601
			$ts = [long]$valueTrimmed
			if($ts -gt 0){
				$dt = ([DateTime]::FromFileTimeutc($ts)).toLocalTime()
				return $dt
			}
			else {
				return $ts
			}
		}
		'windowstruncatedft' { #"utc coded time" or "truncated file time", seconds since 1601
			$ts = [long]$valueTrimmed
			if($ts -gt 0){
				$dt = ([DateTime]::FromFileTimeutc($ts*10000000)).toLocalTime()
				return $dt
			}
			else {
				return $ts
			}
		}
	}

	return $value
	
}
#precheck if both base and final 
#params:
#fileBase,fileFinal:String = absolute file path to files decoded by esedbexport
#returns:
#true when both exist, so comparison is possible
#false + log message if one misses
function NTDSFilesExists(){
param (
	$fileBase,
	$fileFinal
 )	
 	if ((!(Test-Path $fileBase -PathType Leaf) -and !(Test-Path $fileBase -PathType Leaf))) {
		"Expected base and final files dont exist " + $fileBase | out-file $global:logfile -Append
		return $false
	}
	if ((!(Test-Path $fileBase -PathType Leaf))) {
		$fileBase + " doesnt exist" | out-file $global:logfile -Append
		return $false
	}
	if ((!(Test-Path $fileFinal -PathType Leaf))) {
		$fileFinal + "doesnt exist" | out-file $global:logfile -Append
		return $false
	}
	return $true
}
#adds an entry to the global file report
#params:
#changes:String = message
#path:String = file path
#returns: nothing
function addToFilesReport(){
	param (
		$changes,
		$path
	)
	$obj = [PSCustomObject]@{
		Changes = $changes
		Path = $path
	}
	$global:FilesReport += $obj
}
#adds an entry to the global NTDS report
#params:
#source:String = which NTDS db-table
#changes:String = message
#context:String = contextual information to the changes message
#returns: nothing
function addToNTDSReport(){
	param (
		$source,
		$changes,
		$context
	)
	$obj = [PSCustomObject]@{
		Source = $source
		Changes = $changes
		Context = $context
	}
	$global:NTDSReport += $obj
}
#adds an entry to the global UAL report
#params:
#source:String = which row in UAL
#changes:String = message
#context:String = contextual information to the changes message
#returns: nothing
function addToUALReport(){
	param (
		$source,
		$changes,
		$context
	)
	$obj = [PSCustomObject]@{
		Source = $source
		Changes = $changes
		Context = $context
	}
	$global:UALReport += $obj
}
#adds an entry to the global timeline report
#params:
#time:DateTime = when does the change happen
#source:String = where does it come from
#headline:String = short info
#eventdetails:String = contextual information to the changes message
#returns: nothing
function addToTimeline(){
	param (
		$time,
		$source,
		$headline,
		$eventdetails
	)
	if (($eventdetails -eq $null) -and ($headline -eq $null)) {
		return
	}
	if (($eventdetails -ne $null)){
		$eventClean = $eventdetails.replace("`"","'").replace(",",";") #clean for csv output
	}
	$obj = [PSCustomObject]@{
		Time = $time
		Source = $source
		Headline = $headline
		Eventdetails = $eventClean
	}
	$global:timeline += $obj

}
#gives string of all non-null unchanged values in changes object
#params:
#changes:PSObject[] = csv-diff unchanged object array
#returns:String = all unchanged values
function NTDSdatatableAllChangedUnchanged(){
param (
	$changes
)
	$allUnchanged = ""
	foreach($unchangedColumn in $changes.unchanged.PSObject.Properties) {
		$attr = $unchangedColumn.Name
		$value = $changes.unchanged.$attr
		if($value.Length -gt 0){
			if($dateAttributes.ContainsKey($attr)){ #its a date
				$func = $dateAttributes[$attr]
				$dateValue = NTDStoDate $func $value
				$allUnchanged += $attr+"="+$dateValue+"`n"
			}
			else {
				$allUnchanged += $attr+"="+$value+"`n"			
			}			
		}


		
	}
	return $allUnchanged
}
#in case an NTDS datatable entry has been added or removed
#gives a string of ALL these values
#params:
#addrem:PSObject[] = csv-diff added or removed object array
#returns:String = all values
function NTDSdatatableAllSummary(){
param (
	$addrem
)
	$all = ""
	foreach($col in $addrem.PSObject.Properties) {
		$attr = $col.Name
		$value = $addrem.$attr
		if($value.Length -gt 0){
			if($dateAttributes.ContainsKey($attr)){ #its a date
				$func = $dateAttributes[$attr]
				$dateValue = NTDStoDate $func $value
				$all += $attr+"="+$dateValue+"`n"
			}
			else {
				$all += $attr+"="+$value+"`n"			
			}			
		}
	}
	return $all
}
#in case an NTDS sd_table entry has been added or removed
#gives a string of ALL these values
#params:
#addrem:PSObject[] = csv-diff added or removed object array
#returns:String = all values
function NTDSsd_tableAllSummary(){
param (
	$addrem
)
	$summary = ""
	foreach($col in $addrem.PSObject.Properties){
		$attr = $col.Name
		$value = $addrem.$attr
		$summary += $attr+"="+$value+"`n"
	}
	return $summary
}
#returns the string for the eventdetails column for the timeline report for NTDS datatable to quickliy identify the entry. e.g. USER_PRINCIPLE_NAME
#params:
#changes:PSOBject[] = csv-diff changes object
#returns:String = summary
function NTDSdatatableSummaryChanged(){
param (
	$changes
)	
	$summary = "Belongs to row: DNT_Col "
	$summary += $changes.key
	
	if($changes.changes.ATT_USER_PRINCIPAL_NAME -ne $null ){ #ATTm590480
		$summary += ";ATT_USER_PRINCIPAL_NAME "
		$summary += $changes.changes.ATT_USER_PRINCIPAL_NAME
	}
	if($changes.unchanged.ATT_USER_PRINCIPAL_NAME -ne $null){ #ATTm590480
		$summary += ";ATT_USER_PRINCIPAL_NAME "
		$summary += $changes.unchanged.ATT_USER_PRINCIPAL_NAME
	}
	if($changes.changes.ATT_RDN -ne $null){ #ATTm589825
		$summary += ";RDN "
		$summary += $changes.changes.ATT_RDN
	}
	if($changes.unchanged.ATT_RDN -ne $null){ #ATTm589825
		$summary += ";RDN "
		$summary += $changes.unchanged.ATT_RDN
	}
	return $summary
}
#
#NTDSProcess
#called for each by esedbexport exported file
#
#params:
#NTDStable:String = a value out of constant-array $esedbexport_filenames, like eg. datatable.4
#changes:Object[] = JSON, example follows:
#@{added=System.Object[]; removed=System.Object[]; changed=System.Object[]; columns_added=System.Object[]; columns_removed=System.Object[]}
# added: [],
# removed: [],
# changed: [
# "changes": {
#        "cnt_col": [
#           "24", #vorher
#           "25" #nachher
#        ]
# },
# "unchanged": {
	# "DNT_col": "1554",
	# ...
	#
#  }
#}
#],
#"columns_added":  [],
#"colums_removed": []
#
#returns: nothing
function NTDSProcess(){
param (
	$changes,
	$NTDStable
)
	#$endTimeMinusOne = ($global:endTime).AddSeconds(-1)
	if($NTDStable -eq "datatable.4"){
		$jsonPSObject = ConvertFrom-Json -InputObject $changes
		
		if($jsonPSObject.changed.Length -gt 0){
			
			foreach($changed in $jsonPSObject.changed) {
				#"datatable key changed: " + $changed.key | out-file $global:logfile -Append #the given KEY which changed
				#"Row belongs to ATT_USER_PRINCIPAL_NAME:" + $changed.unchanged.ATTm590480 | out-file $global:logfile -Append #ATT_USER_PRINCIPAL_NAME
				#"and Relative Distinguished Name:" + $changed.unchanged.ATTm589825 | out-file $global:logfile -Append
				$rowSummary = NTDSdatatableSummaryChanged $changed
				"Changed row:" + $changed.key | out-file $global:logfile -Append
				$no = ($changed.changes.PSObject.Properties | Measure-Object).Count
				"No of changed columns:" + $no | out-file $global:logfile -Append
				$reportSource = "Datatable row " + $changed.key + " changed"
				$reportChanges = ""
				foreach($changedColumn in $changed.changes.PSObject.Properties) {
					$attr = $changedColumn.Name
					"Changed column:" + $attr | out-file $global:logfile -Append #ATTj590198
					if($dateAttributes.ContainsKey($attr)){ #its a date
						$func = $dateAttributes[$attr]
						$oldValue = NTDStoDate $func $changed.changes.$attr[0]
						if($oldValue.GetType() -eq [DateTime]){
							$oldValueString = $oldValue.toString("dd.MM.yy HH:mm:ss")
						}
						else {
							$oldValueString = $oldValue.toString()
						}
						$newValue = NTDStoDate $func $changed.changes.$attr[1]
						if($newValue.GetType() -eq [DateTime]){
							$newValueString = $newValue.toString("dd.MM.yy HH:mm:ss")
						}
						else {
							$newValueString = $newValue.toString()
						}
						$oldValueString+" => "+$newValueString | out-file $global:logfile -Append
						$reportChanges += "The attribute "+$attr+" changed from "+$oldValueString+" to "+$newValueString+"<br/>" 
						$oldDetails = "This attribute has been changed from '"+$oldValueString+"' (this row) to '"+$newValueString+"'. "+$rowSummary
						$newDetails = "This attribute has been changed from '"+$oldValueString+"' to '"+$newValueString+"' (this row). "+$rowSummary
						addToTimeline $oldValue "NTDS.datatable" $attr" former timestamp" $oldDetails
						addToTimeline $newValue "NTDS.datatable" $attr" new timestamp" $newDetails
					
					}
					else {
						"'"+$changed.changes.$attr[0]+"' => '"+$changed.changes.$attr[1]+"'" | out-file $global:logfile -Append
						$reportChanges += "The attribute "+$attr+" changed from '"+$changed.changes.$attr[0]+"' to '"+$changed.changes.$attr[1]+"'<br/>"
						#in that case we assume that this non-date value has changed at ATT_WHEN_CHANGED
						#because there are only two changed values and one is ATT_WHEN_CHANGED
						if( ($changed.changes.ATT_WHEN_CHANGED -ne $null) -and ($changed.changes.PSObject.Properties.Length -eq 2)){
							$func = $dateAttributes["ATT_WHEN_CHANGED"]
							$whenChanged = NTDStoDate $func $changed.changes.ATT_WHEN_CHANGED
							$headline = $attr+" changed from '"+$changed.changes.$attr[0]+"' to '"+$changed.changes.$attr[1]+"'"
							$details = "Because ATT_WHEN_CHANGED is set to this time, we assume, that this only changed value had been set at this time. "+$rowSummary	
							addToTimeline $whenChanged "NTDS.datatable" $headline $details	
						}
						else {
							$headline = $attr+" changed from '"+$changed.changes.$attr[0]+"' to '"+$changed.changes.$attr[1]+"'"
							
							$details = "No information about the time when this value has been set except that it obviously changed between begin and end. Thats why we order it 1 second before the end. "+$rowSummary	
							#addToTimeline $endTimeMinusOne "NTDS.datatable" $headline $details							
						}


					}
				}
							
				$unchangedSummary = NTDSdatatableAllChangedUnchanged $changed
				"Unchanged non-null values:`n"+$unchangedSummary | out-file $global:logfile -Append
				addToNTDSReport $reportSource $reportChanges $unchangedSummary
			}
		}
		else {
			"No datatable row changed" | out-file $global:logfile -Append
		}
		if($jsonPSObject.added.Length -gt 0){
			"No of added rows:" + $jsonPSObject.added.Length | out-file $global:logfile -Append
			foreach($added in $jsonPSObject.added) {
				$reportSource = "datatable row added"
				$addedSummary = NTDSdatatableAllSummary $added
				"Added:`n"+$addedSummary | out-file $global:logfile -Append
				$reportChanges = "New row key: " + $added.DNT_col
				addToNTDSReport $reportSource $reportChanges $addedSummary
			}
		}
		else {
			"No datatable row added" | out-file $global:logfile -Append 
		}
		if($jsonPSObject.removed.Length -gt 0){
			"No of removed rows:" + $jsonPSObject.removed.Length | out-file $global:logfile -Append
			foreach($removed in $jsonPSObject.removed) {
				$reportSource = "datatable row removed"
				$removedSummary = NTDSdatatableAllSummary $removed
				"Removed:`n"+$removedSummary | out-file $global:logfile -Append
				$reportChanges = "Removed row key: " + $removed.DNT_col
				addToNTDSReport $reportSource $reportChanges $removedSummary
			}
		}
		else {
			"No datatable row removed" | out-file $global:logfile -Append
		}
		if($jsonPSObject.columns_added.Length -gt 0){
			"No of added columns:" + $jsonPSObject.columns_added.Length | out-file $global:logfile -Append
			foreach($coladded in $jsonPSObject.columns_added) {
				$reportSource = "datatable column added"
				"Added column: "+$coladded+" (manual check mandatory)"  | out-file $global:logfile -Append
				$reportChanges = "New column: " + $coladded
				addToNTDSReport $reportSource $reportChanges "Manual check mandatory"
			}
		}
		else {
			"No datatable columns added" | out-file $global:logfile -Append 
		}
		if($jsonPSObject.columns_removed.Length -gt 0){
			"No of removed columns:" + $jsonPSObject.columns_removed.Length | out-file $global:logfile -Append
			foreach($colremoved in $jsonPSObject.columns_removed) {
				$reportSource = "datatable column removed"
				"Removed column: "+$colremoved  | out-file $global:logfile -Append
				$reportChanges = "Removed column: " + $colremoved
				addToNTDSReport $reportSource $reportChanges ""
			}
		}
		else {
			"No datatable columns removed" | out-file $global:logfile -Append
		}
	}
	if($NTDStable -eq "sd_table.8"){
		$jsonPSObject = ConvertFrom-Json -InputObject $changes
		
		if($jsonPSObject.changed.Length -gt 0){
			foreach($changed in $jsonPSObject.changed) {
				$rowSummary = NTDSdatatableSummaryChanged $changed
				"Changed row:" + $changed.key | out-file $global:logfile -Append
				$no = ($changed.changes.PSObject.Properties | Measure-Object).Count
				"No of changed columns:" + $no | out-file $global:logfile -Append
				$reportSource = "sd_table row " + $changed.key + " changed"
				$reportChanges = ""
				foreach($changedColumn in $changed.changes.PSObject.Properties) {
					$attr = $changedColumn.Name
					"Changed column:" + $attr | out-file $global:logfile -Append
					"'"+$changed.changes.$attr[0]+"' => '"+$changed.changes.$attr[1]+"'" | out-file $global:logfile -Append
					$reportChanges += "The attribute "+$attr+" changed from '"+$changed.changes.$attr[0]+"' to '"+$changed.changes.$attr[1]+"'<br/>"
				}
				$unchangedSummary = NTDSdatatableAllChangedUnchanged $changed
				"Unchanged non-null values:`n"+$unchangedSummary | out-file $global:logfile -Append	
				addToNTDSReport $reportSource $reportChanges $unchangedSummary			
			}

			
		}
		else {
			"No sd_table row changed" | out-file $global:logfile -Append
		}
		if($jsonPSObject.added.Length -gt 0){
			"No of added rows:" + $jsonPSObject.added.Length | out-file $global:logfile -Append
			foreach($added in $jsonPSObject.added) {
				$reportSource = "sd_table row added"
				$addedSummary = NTDSsd_tableAllSummary $added
				"Added:`n"+$addedSummary | out-file $global:logfile -Append
				$reportChanges = "New row key: " + $added.DNT_col
				addToNTDSReport $reportSource $reportChanges $addedSummary
			}
		}
		else {
			"No sd_table row added" | out-file $global:logfile -Append 
		}
		if($jsonPSObject.removed.Length -gt 0){
			"No of removed rows:" + $jsonPSObject.removed.Length | out-file $global:logfile -Append
			foreach($removed in $jsonPSObject.removed) {
				$reportSource = "sd_table row added"
				$removedSummary = NTDSsd_tableAllSummary $removed
				"Removed:`n"+$removedSummary | out-file $global:logfile -Append
				$reportChanges = "Removed row key: " + $removed.DNT_col
				addToNTDSReport $reportSource $reportChanges $removedSummary
			}
		}
		else {
			"No sd_table row removed" | out-file $global:logfile -Append
		}
		if($jsonPSObject.columns_added.Length -gt 0){
			"No of added columns:" + $jsonPSObject.columns_added.Length | out-file $global:logfile -Append
			foreach($coladded in $jsonPSObject.columns_added) {
				$reportSource = "sd_table column added"
				"Added column: "+$coladded+" (manual check mandatory)"  | out-file $global:logfile -Append
				$reportChanges = "New column: " + $coladded
				addToNTDSReport $reportSource $reportChanges "Manual check mandatory"
			}
		}
		else {
			"No sd_table columns added" | out-file $global:logfile -Append 
		}
		if($jsonPSObject.columns_removed.Length -gt 0){
			"No of removed columns:" + $jsonPSObject.columns_removed.Length | out-file $global:logfile -Append
			foreach($colremoved in $jsonPSObject.columns_removed) {
				$reportSource = "sd_table column removed"
				"Removed column: "+$colremoved  | out-file $global:logfile -Append
				$reportChanges = "Removed column: " + $colremoved
				addToNTDSReport $reportSource $reportChanges ""
			}
		}
		else {
			"No sd_table columns removed" | out-file $global:logfile -Append
		}
	}

}
#replaces all Attribute IDs to readable names via the lookup table
#params:
#string:String = the whole object given by csv-diff
#NTDStable:String = name of the table exported by esedbexport
#returns: String = the whole object given by csv-diff with replaced Attribute IDs
function NTDSAttLookupAll(){
	param (
		$string,
		$NTDStable
	)
	if($NTDStable -eq "datatable.4"){
		foreach($attId in $attIdLookup.Keys){
			$searchstring = '"'+$attId+'"' #search string with quotes to prevent eg ATTm1572870 is replaced with ATTm15
			$replacestring = '"'+$attIdLookup.$attId+'"'
			$string = $string.replace($searchstring, $replacestring) 
		}		
	}

	return $string
}
#checks if a file has changed by MD5 hash, both files need to exist!
#params:
#fileBase,fileFinal:String = Absolute file paths to file
#returns: true if has changed, otherwise false
# if one file cant be accessed, will return false
function hasChangedByHash(){
 param (
   $fileBase,
   $fileFinal
 )
	try {
		
		$FileHashFinal = Get-FileHash $fileFinal -Algorithm MD5 -ErrorAction stop
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		'Not Found '+ $fileFinal | out-file $global:logfile -Append #$Error[0].Exception.GetType().FullName
		addToFilesReport "NOT FOUND " $fileFinal
		return $false
	}
	catch [System.UnauthorizedAccessException] {
		'Unauthorized Failed to compare '+ $fileFinal | out-file $global:logfile -Append #$Error[0]
		addToFilesReport "Unauthorized Failed to compare " $fileFinal
		return $false
	}
	catch [System.IO.IOException] {
		addToFilesReport "IOException Failed to compare" $fileFinal
		'IOException Failed to compare '+ $fileFinal | out-file $global:logfile -Append #$Error[0]
		return $false
	}
	catch {
		addToFilesReport "Failed to compare file because of any kind of exception" $fileFinal
		'Failed to compare file because of any kind of exception '+ $fileFinal | out-file $global:logfile -Append #$Error[0]
		return $false
	}
	#when we come to this point, the final file is accessible
	try {
		$FileHashBase = Get-FileHash $fileBase -Algorithm MD5 -ErrorAction stop
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		#when the base file is not there, we take the final file anyway
		return $true
	}
	catch [System.UnauthorizedAccessException] {
		addToFilesReport "FinalFile was accessible, but PreFile is unauthorized" $fileBase
		'FinalFile was accessible, but PreFile is unauthorized '+$fileBase | out-file $global:logfile -Append #$Error[0]
		return $false
	}
	catch [System.IO.IOException] {
		addToFilesReport 'FinalFile was accessible, but PreFile had an IOException ' $fileBase
		'FinalFile was accessible, but PreFile had an IOException '+$fileBase | out-file $global:logfile -Append #$Error[0]
		return $false
	}
	catch {
		addToFilesReport 'FinalFile was accessible, but PreFile had any kind of exception ' $fileBase
		'FinalFile was accessible, but PreFile had any kind of exception '+$fileBase | out-file $global:logfile -Append #$Error[0]
		return $false
	}
	if ($FileHashFinal.Hash -eq $FileHashBase.Hash) {
		return $false
	}
	else {
		return $true
	}
}
#############################
# BEGIN
#############################

#user input name
$namePattern = "^[a-zA-Z0-9]+$"
while ($name -eq $null){
	$name = read-host "Enter name used to capture"
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
#check if result folder already exists, what is not allowed if not in debug mode
$resultFolder = Join-Path $targetfolder $name"Results"
if (Test-Path $resultFolder -PathType Container) {
	#Exists 
	if($debug){
		Remove-Item -Recurse -Force $resultFolder
	}
	else {
		Write-host "Result folder already exists. Delete first.";
		exit
	}
}
New-Item -Path $resultFolder -ItemType Directory -Force | out-null
#globals
$global:logfile = Join-Path $resultFolder $logfileName
$global:timeline = @()
$global:NTDSReport = @()
$global:UALReport = @()
$global:FilesReport = @()
#check if base/final exist
$baseFolder = Join-Path $targetfolder $name"Base"
$finalFolder = Join-Path $targetfolder $name"Final"
if (!(Test-Path $baseFolder -PathType Container) -or !(Test-Path $finalFolder -PathType Container)) {
	#Exists 
	Write-host "Expected folders in $targetfolder dont exist. Where is your captured data?";
	exit
}
else {
	"Found Base/Final folder" | out-file $global:logfile -Append
}
#read the start and endtime from files created by capture module
$startTimeFile = Join-Path $baseFolder "starttime.dcdif"
$startTimeString = Get-Content -Path $startTimeFile -TotalCount 1 #yyyyMMddHHmmss
$global:startTime = [datetime]::ParseExact($startTimeString,'yyyyMMddHHmmss',$null)
$endTimeFile = Join-Path $finalFolder "endtime.dcdif"
$endTimeString = Get-Content -Path $endTimeFile -TotalCount 1 #yyyyMMddHHmmss
$global:endTime = [datetime]::ParseExact($endTimeString,'yyyyMMddHHmmss',$null)



#############################
# VOLUME SHADOW COPIES
#############################
$VSCRoot = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"

#if the mountpoints are already there, we unmount them first
$vscBaseFolder = Join-Path $targetfolder $name"BaseVSC"
if (Test-Path $vscBaseFolder -PathType Container) {
	cmd /c rmdir $vscBaseFolder #verified command for deleting symbolic link, not its contents!
}
$vscFinalFolder = Join-Path $targetfolder $name"FinalVSC"
if (Test-Path $vscFinalFolder -PathType Container) {
	cmd /c rmdir $vscFinalFolder #verified command for deleting symbolic link, not its contents!
}
#mount the VSCs
#mklink will create folder
$baseVSCNoFile = Join-Path $baseFolder "vscNo.dcdif"
$baseVSCNo = Get-Content -Path $baseVSCNoFile -TotalCount 1
$baseVSCRoot = $VSCRoot + $baseVSCNo.Trim() + "\" #trailing slash is mandatory!
cmd /c mklink /d $vscBaseFolder $baseVSCRoot

$finalVSCNoFile = Join-Path $finalFolder "vscNo.dcdif"
$finalVSCNo = Get-Content -Path $finalVSCNoFile -TotalCount 1
$finalVSCRoot = $VSCRoot + $finalVSCNo.Trim() + "\" #trailing slash is mandatory!
cmd /c mklink /d $vscFinalFolder $finalVSCRoot

#created the -Path parameter for Get-Childitem by reading the $fileChangesPathes configuration parameter from above
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

#read all files from volume shadow copies
$childsBase = Get-ChildItem -Path $childsBasePathes -Recurse -Force -ErrorVariable FailedItemsBase -ErrorAction SilentlyContinue -Attributes !Directory
$childsFinal = Get-ChildItem -Path $childsFinalPathes -Recurse -Force -ErrorVariable FailedItemsFinal -ErrorAction SilentlyContinue -Attributes !Directory

#create empty lists for EVTX files when walking past them
$changedEvtxFiles = New-Object System.Collections.Generic.List[System.Object]
$newEvtxFiles = New-Object System.Collections.Generic.List[System.Object]
#count files for progress bar
$filesAmount = ( $childsFinal | Measure-Object ).Count


#iterate over all Final files
$filesProgress = 0
$childsFinal | Foreach-Object { #$finalVSCRoot
	#Get-Member -InputObject $_
	$supposedMatchingBaseFile = $_.FullName.replace("FinalVSC","BaseVSC")
	#Write-Host $supposedMatchingBaseFile
	#if this file is not in Pre/Base, it is a new file
	if ((!(Test-Path $supposedMatchingBaseFile -PathType Leaf))) {
		$relativePath = $_.FullName -split "FinalVSC"
			"NEW FILE: " + $relativePath[1] | out-file $global:logfile -Append
			addToFilesReport "New file" $relativePath[1]
			Copy-Item $_.FullName -Destination $resultFolder -ErrorAction SilentlyContinue		
		if (($_.FullName -match '.evtx$')){
			
			$newEvtxFiles.add($_.Name)
		}	
	}
	else {
		if (hasChangedByHash $supposedMatchingBaseFile $_.FullName ){
			$relativePath = $_.FullName -split "FinalVSC"
			"CHANGED: " + $relativePath[1] | out-file $global:logfile -Append
			addToFilesReport "Changed file" $relativePath[1]
			Copy-Item $_.FullName -Destination $resultFolder -ErrorAction SilentlyContinue
			if ($_.FullName -match '.evtx$'){
				$changedEvtxFiles.add($relativePath[1])
			}
		}
	}
	$filesProgress++
	$percent = [math]::Round($filesProgress * 100 / $filesAmount,2)
	Write-Progress -Activity "Searching changed files" -Status "$percent% of total $filesAmount files done" -PercentComplete $percent
}
#iterate over all Base files to also get deleted files
$childsBase | 
	Foreach-Object {
		#find files not in Final
		$supposedMatchingFinalFile = $_.FullName.replace("BaseVSC","FinalVSC")
		if ((!(Test-Path $supposedMatchingFinalFile -PathType Leaf))) {
			$relativePath = $_.FullName -split "BaseVSC"
			"DELETED: " + $relativePath[1] | out-file $global:logfile -Append
			addToFilesReport "Deleted file" $relativePath[1]
		}
	}
#todo merge arrays and remove duplicates by relative path
#output read/compare errors to logfile
"Failed to compare items base " + $FailedItemsBase.Count + ":" | out-file $global:logfile -Append
$FailedItemsBase | Foreach-Object {
	$_.Exception.Message + " in " + $_.TargetObject | out-file $global:logfile -Append
	addToFilesReport "Failed to compare" $_.TargetObject
}
"Failed to compare items final " + $FailedItemsFinal.Count + ":" | out-file $global:logfile -Append
$FailedItemsFinal | Foreach-Object {
	$_.Exception.Message + " in " + $_.TargetObject | out-file $global:logfile -Append
	addToFilesReport "Failed to compare" $_.TargetObject

}
#############################
# EVTX
#############################
#process NEW (!) EVTX files detected while iterating VSCs
if($newEvtxFiles.Count -gt 0){
	"Processing NEW EVTX files" | out-file $global:logfile -Append
	$newEvtxFiles | Foreach-Object { #elements are filenames. because file is new, it resides in resultFolder
		$evtxFile = Join-Path $resultFolder $_
		"Processing new evtx file: " + $evtxFile | out-file $global:logfile -Append
		if((Test-Path $evtxFile -PathType Leaf) -and (Get-Item $evtxFile).length -gt 0kb){
			#read the events from file
			Get-WinEvent -Path $evtxFile | Foreach-Object {
				$dateTimeObj = [DateTime]$_.TimeCreated #toLocalTime = no effect on HTML time column format. toString uses current system culture format.
				$headline = "EventId: " + $_.Id + " "
				$headline += $_.Message -split "`r?`n" | Select-Object -First 1
				if ($_.Message.Length -eq 0){ #sometimes there is no detail-message
					$evtDetails = "dcdiff notice: no details in this event. examine file with eventviewer." 
				}
				else {
					$evtDetails = $_.Message
				}
				#add event to timeline report
				addToTimeline $dateTimeObj $_.LogName $headline $evtDetails #$_.FormatDescription()
			}
		}
		else {
			"File "+$evtxFile+" has zero-size" | out-file $global:logfile -Append
		}
	}
}
#process CHANGED EVTX files detected while iterating VSCs
if($changedEvtxFiles.Count -gt 0){
	"Processing CHANGED EVTX files" | out-file $global:logfile -Append
	$changedEvtxFiles | Foreach-Object { #elements are relative paths after base/finalVSC
		$baseEvtxFile = Join-Path $vscBaseFolder $_
		$finalEvtxFile = Join-Path $vscFinalFolder $_
		$evtxFile = $_ #will confuse with next loop
		"Processing changed evtx file: " + $_| out-file $global:logfile -Append
		if( ((Get-Item $baseEvtxFile).length -gt 0kb) -and ((Get-Item $finalEvtxFile).length -gt 0kb)){
			#read the starttime to only decode events after the start of the attack
			$time = $global:startTime
			#produces more output also before startime:
			#$time = $null
			#Get-WinEvent -Path $baseEvtxFile  | Select-Object -First 1 | Foreach-Object {
			#	$time = $_.TimeCreated #get latest eventtimedate id whatever from BASE
			#	"first:" + $time | Write-Host
			#}		
			if ($time -ne $null){ # 
				Get-WinEvent -FilterHashtable @{Path=$finalEvtxFile;StartTime=$time} -erroraction 'silentlycontinue' | Sort-Object -Property TimeCreated | Foreach-Object {
					#"Event created:" + $_.TimeCreated + "`n" + $_.FormatDescription() | out-file $global:logfile -Append
					$headline = "EventId: " + $_.Id + " "
					$headline += $_.Message -split "`r?`n" | Select-Object -First 1
					$dateTimeObj = [DateTime]$_.TimeCreated #.toLocalTime = no effect on HTML time column format.
					#$_.Id | Write-Host
					if ($_.Message.Length -eq 0){ #sometimes there is no detail-message
						$evtDetails = "dcdiff notice: no details in this event. examine file with eventviewer." 
					}
					else {
						$evtDetails = $_.Message
					}
					#add event to timeline report
					addToTimeline $dateTimeObj $_.LogName $headline $evtDetails #FormatDescription()
				}				
			}
			else {
				"File "+$evtxFile+" has no event or no TimeCreated value" | out-file $global:logfile -Append
			}
		}
		else {
			"File "+$evtxFile+" has zero-size" | out-file $global:logfile -Append
		}
	}
}

#############################
# NTDS
#############################
#check if ntds.dit files are there
$baseNTDS = Join-Path $baseFolder "ntds.dit"
$finalNTDS = Join-Path $finalFolder "ntds.dit"
if (!(Test-Path $baseNTDS -PathType Leaf) -or !(Test-Path $finalNTDS -PathType Leaf)) {
	#Not exists 
	Write-host "Expected ntds files in $baseFolder and $finalFolder don't exist. Where is your captured data?";
	exit
}
else {
	"Found ntds.dit in Base and Final" | out-file $global:logfile -Append
}
#use esedbexport to export tables
$currentPath = Get-Location #esedbexport creates subdir ntds.dit.export in current dir
$NTDSExportPath = Join-Path $resultFolder "ntds.dit.export"
$NTDSExportPathBase = Join-Path $resultFolder "base.ntds.dit.export"
$NTDSExportPathFinal = Join-Path $resultFolder "final.ntds.dit.export"
Set-Location -Path $resultFolder
cmd /c esedbexport -m tables $baseNTDS 
Rename-Item $NTDSExportPath $NTDSExportPathBase

cmd /c esedbexport -m tables $finalNTDS 
Set-Location -Path $currentPath
Rename-Item $NTDSExportPath $NTDSExportPathFinal

#meaning of most tables unknown. primary key needed for comparison but none suitable. some tables empty anyway
#files respectivly tables created by esedbexport 
$esedbexport_filenames = @('datatable.4','hiddentable.6','link_history_table.10','link_table.5','MSysDefrag2.11','MSysLocales.3','MSysObjects.0','MSysObjectsShadow.1','MSysObjids.2','quota_rebuild_progress_table.13','quota_table.12','sd_table.8','sdpropcounttable.9','sdproptable.7') 
$esedbexport_uniqueKey = @('DNT_col','usn_col','history_ID','','','','','','','','','sd_id','','')
#Loop over all NTDS files/tables
For($I=0;$I -lt $esedbexport_filenames.count;$I++){
	$key = $esedbexport_uniqueKey[$I]
	$baseTSVFile = Join-Path $NTDSExportPathBase $esedbexport_filenames[$I]
	$finalTSVFile = Join-Path $NTDSExportPathFinal $esedbexport_filenames[$I]
	"Comparison of " + $baseTSVFile + " AND " + $finalTSVFile | out-file $global:logfile -Append
	#pre check if pathes arent empty
	if (($baseTSVFile -eq $null) -or ($finalTSVFile -eq $null)){
		"One value was null " + $I | out-file $global:logfile -Append
		continue
	}
	if (NTDSFilesExists $baseTSVFile $finalTSVFile ) { #true when both exist, false + log message if one misses
		#if tables havent changed, we dont need to do any comparison
		if (hasChangedByHash $baseTSVFile $finalTSVFile ){
			if($key.Length -gt 0){
				$tsvdataBase = Import-Csv -Delimiter "`t" -Path $baseTSVFile
				$tsvdataFinal = Import-Csv -Delimiter "`t" -Path $finalTSVFile
				if(($tsvdataBase.count -gt 1) -or ($tsvdataFinal.count -gt 1)){ #check if anything is in the files
					#start csv-diff
					"cmd /c csv-diff $baseTSVFile $finalTSVFile --key=$key --show-unchanged --json" | out-file $global:logfile -Append
					$ntdsJSON = cmd /c csv-diff $baseTSVFile $finalTSVFile --key=$key --show-unchanged --json
					$ntdsJSONString = $ntdsJSON -Join "`n"
					#replace all AttributeIDs
					$ntdsJSONReplaced = NTDSAttLookupAll $ntdsJSONString $esedbexport_filenames[$I]
					if($debug){
						$ntdsJSONReplaced | out-file $global:logfile -Append
					}
					#start main analysis of changes
					$postProcess = NTDSProcess $ntdsJSONReplaced $esedbexport_filenames[$I]
					
				}
				else {
					"CSV/TSV files consisting only the header row: " + $esedbexport_filenames[$I] | out-file $global:logfile -Append
				}
			}
			else {
				"Files has changed but missing primary key for comparison. Manual comparison needed for " + $esedbexport_filenames[$I] | out-file $global:logfile -Append
			}
		}
		else {
			"Files hasnt changed: " + $esedbexport_filenames[$I] | out-file $global:logfile -Append
		}

	}
}

#############################
# UAL
#############################
#used to summarize whole added or removed rows
#params:
#addrem:PSObject = one added or removed object
#returns:
#string with all values
function UALAllSummary(){
param (
	$addrem
)
	$all = ""
	foreach($col in $addrem.PSObject.Properties) {
		$attr = $col.Name
		$value = $addrem.$attr
		if($value.Length -gt 0){
			if($attr -eq "LastAccess" -or $attr -eq "InsertDate"){ #its a date
				$valueUTC = [DateTime] $value
				$valueLocal = $valueUTC.ToLocalTime()
				$valueLocalString = $valueLocal.toString("dd.MM.yy HH:mm:ss")
				$all += $attr+"="+$valueLocalString+"`n"
			}
			else {
				$all += $attr+"="+$value+"`n"					
			}						
		}
	}
	return $all
}
#used to give context to UAL entries in timeline report
#params:
#changes:PSObject = one added or removed object
#returns:
#string with contextual information
function UALSummaryChanged(){
param (
	$changes
)	
	$summary = "UAL; belongs to Line "
	$summary += $changes.key
	
	if($changes.changes.AuthenticatedUserName -ne $null ){ 
		$summary += ";AuthenticatedUserName "
		$summary += $changes.changes.AuthenticatedUserName
	}
	if($changes.unchanged.AuthenticatedUserName -ne $null){ 
		$summary += ";AuthenticatedUserName "
		$summary += $changes.unchanged.AuthenticatedUserName
	}
	$key = "ConvertedAddress (Correlated_HostName(s))"
	if($changes.changes.ATT_RDN -ne $null){ 
		$summary += $key
		$summary += $changes.changes.$key
	}
	if($changes.unchanged.ATT_RDN -ne $null){ 
		$summary += $key
		$summary += $changes.unchanged.$key
	}
	return $summary
}
#all non-null unchanged values of a changes relation
#params:
#changes:PSObject = 
#returns:
#string with all unchanged values
function UALAllChangedUnchanged(){
param (
	$changes
)
	$allUnchanged = ""
	foreach($unchangedColumn in $changes.unchanged.PSObject.Properties) {
		$attr = $unchangedColumn.Name
		$value = $changes.unchanged.$attr
		if($value.Length -gt 0){
			if($attr -eq "LastAccess" -or $attr -eq "InsertDate"){ #its a date
				$valueUTC = [DateTime] $value
				$valueLocal = $valueUTC.ToLocalTime()
				$valueLocalString = $valueLocal.toString("dd.MM.yy HH:mm:ss")
				$allUnchanged += $attr+"="+$valueLocalString+"`n"
			}
			else {
				$allUnchanged += $attr+"="+$value+"`n"					
			}
		}		
	}
	return $allUnchanged
}
#main analysis of UAL changes
#params:
#ual:String = JSON string of csv-diff output
#returns:nothing
function UALProcess(){
param (
	$ual
)
	$UALdateKeys = @("LastAccess","InsertDate")

	$jsonPSObject = ConvertFrom-Json -InputObject $ual #convert JSON to PSObject[]
	#if changes have been detected
	if($jsonPSObject.changed.Length -gt 0){
		foreach($changed in $jsonPSObject.changed) {
			$rowSummary = UALSummaryChanged $changed
			"Changed row:" + $changed.key | out-file $global:logfile -Append
			$no = ($changed.changes.PSObject.Properties | Measure-Object).Count
			"No of changed columns:" + $no | out-file $global:logfile -Append
			$reportSource = "UAL row " + $changed.key + " changed"
			$reportChanged = ""
			foreach($changedColumn in $changed.changes.PSObject.Properties) {
				$attr = $changedColumn.Name
				"Changed column:" + $attr | out-file $global:logfile -Append
				
				#LastAccess/InsertDate format example:
				#LastAccess: "2022-04-20 16:02:38.429254" => "2022-04-20 16:03:50.588222"
				if($attr -eq "LastAccess" -or $attr -eq "InsertDate"){ #its a date
					$oldValueUTC = [DateTime] $changed.changes.$attr[0]
					$oldValue = $oldValueUTC.ToLocalTime()
					$oldValueString = $oldValue.toString("dd.MM.yy HH:mm:ss")
					$newValueUTC = [DateTime] $changed.changes.$attr[1]
					$newValue = $newValueUTC.ToLocalTime()
					$newValueString = $newValue.toString("dd.MM.yy HH:mm:ss")
					$oldValueString+" => "+$newValueString | out-file $global:logfile -Append
					$oldDetails = "This attribute has been changed from "+$oldValueString+" (this row) to "+$newValueString+". "+$rowSummary
					$newDetails = "This attribute has been changed from "+$oldValueString+" to "+$newValueString+" (this row). "+$rowSummary
					$reportChanged += "The attribute "+$attr+" changed from "+$oldValueString+" to "+$newValueString+"<br/>" 
					addToTimeline $oldValue "UAL" $attr" former timestamp" $oldDetails
					addToTimeline $newValue "UAL" $attr" new timestamp" $newDetails
				}
				#DatesAndAccesses field looks like:
				#DatesAndAccesses: "2022-04-10: 355; 2022-04-11: 68; 2022-04-12: 422; 2022-04-13: 296; 2022-04-14: 206; 2022-04-16: 101; 2022-04-17: 264; 2022-04-18: 114; 2022-04-19: 409; 2022-04-20: 344; " => "2022-04-10: 355; 2022-04-11: 68; 2022-04-12: 422; 2022-04-13: 296; 2022-04-14: 206; 2022-04-16: 101; 2022-04-17: 264; 2022-04-18: 114; 2022-04-19: 409; 2022-04-20: 345; "
				elseif($attr -eq "DatesAndAccesses"){
					$old = $changed.changes.$attr[0] -split ";"
					$new = $changed.changes.$attr[1] -split ";"					
					if($new.Length -gt $old.Length){ 
						for ($i=0; $i -lt $old.length; $i++){
							if($new[$i].Trim() -ne $old[$i].Trim()){
								"Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim() | out-file $global:logfile -Append
								$reportChanged += "Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim()+"<br/>"
							}
						}	
						for ($i=$old.length; $i -lt $new.length; $i++){
							"New last access: "+$new[$i].Trim() | out-file $global:logfile -Append
							$reportChanged += "New last access: "+$new[$i].Trim()+"<br/>"
						}
					}
					if($new.Length -eq $old.Length){
						for ($i=0; $i -lt $old.length; $i++){
							if($new[$i].Trim() -ne $old[$i].Trim()){
								"Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim() | out-file $global:logfile -Append
								$reportChanged += "Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim()+"<br/>"
							}
						}	
					}
					if($new.Length -le $old.Length){
						for ($i=0; $i -lt $new.length; $i++){
							if($new[$i].Trim() -ne $old[$i].Trim()){
								"Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim() | out-file $global:logfile -Append
								$reportChanged += "Changed number of last accesses from "+$old[$i].Trim()+" to "+$new[$i].Trim()+"<br/>"
							}
						}	
						for ($i=$new.length; $i -lt $old.length; $i++){
							"Last access removed: "+$old[$i].Trim() | out-file $global:logfile -Append
							$reportChanged += "Last access removed: "+$new[$i].Trim()+"<br/>"
						}						
					}
					#$old[-1] #last element
				}
				else {
					$reportChanged += "The attribute "+$attr+" changed from '"+$changed.changes.$attr[0]+"' to '"+$changed.changes.$attr[1]+"'<br/>"
					"'"+$changed.changes.$attr[0]+"' => '"+$changed.changes.$attr[1]+"'" | out-file $global:logfile -Append
				}
			}
			#create an summary of the unchanged values
			$unchangedSummary = UALAllChangedUnchanged $changed
			"Unchanged non-null values:`n"+$unchangedSummary | out-file $global:logfile -Append
			#add to UAL report
			addToUALReport $reportSource $reportChanged $unchangedSummary			
		}
	}
	else {
		"No UAL row changed" | out-file $global:logfile -Append
	}
	#if a row has been added to UAL
	if($jsonPSObject.added.Length -gt 0){
		"No of added UAL rows:" + $jsonPSObject.added.Length | out-file $global:logfile -Append
		foreach($added in $jsonPSObject.added) {
			$addedSummary = UALAllSummary $added
			"Added UAL:`n"+$addedSummary | out-file $global:logfile -Append
			$reportSource = "UAL row added"
			$reportChanges = "New row key: " + $added.LineNo
			addToUALReport $reportSource $reportChanges $addedSummary
		}
	}
	else {
		"No UAL row added" | out-file $global:logfile -Append 
	}
	#if a row has been removed from UAL
	if($jsonPSObject.removed.Length -gt 0){
		"No of removed UAL rows:" + $jsonPSObject.removed.Length | out-file $global:logfile -Append
		foreach($removed in $jsonPSObject.removed) {
			$removedSummary = UALAllSummary $removed
			"Removed UAL:`n"+$removedSummary | out-file $global:logfile -Append
			$reportSource = "UAL row removed"
			$reportChanges = "Removed row key: " + $removed.LineNo
			addToUALReport $reportSource $reportChanges $removedSummary
		}		
	}
	else {
		"No UAL row removed" | out-file $global:logfile -Append
	}
	#columns_added / columns_removed skipped because havent seen before in UAL!
		
		
}
#decodes the ESEDB .mdb files to CSV and then via csv-diff to JSON
#params:
#file: = name of file
#baseFolder: = folder where Base $file is in 
#finalFolder: = folder where Final $file is in
#returns:nothing
function parseUAL(){
 param (
   $file,
   $baseFolder,
   $finalFolder
 )
	$baseUAL = Join-Path $baseFolder $file
	$baseUALCSV = Join-Path $baseFolder $file".csv"
	$finalUAL = Join-Path $finalFolder $file
	$finalUALCSV = Join-Path $finalFolder $file".csv"
	#convert with KString-mod to CSV
	python KStrike.py $baseUAL $baseUALCSV  
	python KStrike.py $finalUAL $finalUALCSV 
	#compare with csv-diff
	"cmd /c csv-diff $baseUALCSV $finalUALCSV --key=LineNo --show-unchanged --json" | out-file $global:logfile -Append
	$ualJSON = cmd /c csv-diff $baseUALCSV $finalUALCSV --key=LineNo --show-unchanged --json
	$ualJSONString = $ualJSON -Join "`n"
	if($debug){
		$ualJSONString | out-file $global:logfile -Append
	}
	#analyse csv-diff output
	UALProcess $ualJSONString
}
$ualFile = "current_stopsvc.mdb" #debug. tested different methods: "current_esentutl.mdb"

"Comparison of UAL in file " + $ualFile | out-file $global:logfile -Append
parseUAL $ualFile $baseFolder $finalFolder

#############################
# REPORT
#############################
#
#define CSS for all reports 
$header = @"
<style>
BODY {font-family: Verdana, Arial, Helvetica, sans-serif;}
TH {background-color: #6495ED;}
TD {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse; }
</style>
"@
#NTDS RREPORT
$ntdsReportFile = Join-Path $resultFolder $ntdsReportFilename 
$NTDSReportListContent = "<h1>NTDS</h1>"
$global:NTDSReport | Foreach-Object {
	$prec = "<h2>"+$_.Source+"</h2>"
	$NTDSReportListContent += $_ | ConvertTo-Html -As List -Property Changes,Context -Fragment -PreContent $prec
}
$ntdsReportString = ConvertTo-HTML -Head "$header" -Body "$NTDSReportListContent" -Title "NTDS" -PostContent "<p>&nbsp;</p><p>Creation Date: $(Get-Date)<p>"
$ntdsReportString.replace("&lt;br/&gt;","<br/>") | Out-File $ntdsReportFile

#UAL RREPORT
$ualReportFile = Join-Path $resultFolder $ualReportFilename 
$UALReportListContent = "<h1>UAL</h1>"
$global:UALReport | Foreach-Object {
	$prec = "<h2>"+$_.Source+"</h2>"
	$UALReportListContent += $_ | ConvertTo-Html -As List -Property Changes,Context -Fragment -PreContent $prec
}
$ualReportString = ConvertTo-HTML -Head "$header" -Body "$UALReportListContent" -Title "UAL" -PostContent "<p>&nbsp;</p><p>Creation Date: $(Get-Date)<p>"
$ualReportString.replace("&lt;br/&gt;","<br/>") | Out-File $ualReportFile

#FILE RREPORT
$prec = "<h1>Files</h1>Please find a copy of the files in the results folder " + $resultFolder.ToString()
$filesReportFile = Join-Path $resultFolder $filesReportFilename 
$global:FilesReport | Sort-Object Changes | ConvertTo-Html -Head "$header" -PreContent $prec -PostContent "<p>&nbsp;</p><p>Creation Date: $(Get-Date)<p>" | Out-File $filesReportFile


#load main report template and replace title
$mainReportFile = Join-Path $resultFolder $mainReportFilename
$mainReportFileContent = Get-Content -Path $mainReportTemplateFilename
$mainReportFileContent.replace("<title>dcdiff</title>","<title>" + $name + "</title>") | out-file $mainReportFile


Invoke-Item $mainReportFile #open file

#############################
# TIMELINE
#############################
#add start/endtime to timeline
addToTimeline $global:startTime "dcdiff" "begin" "The point of time you captured the base-state"
addToTimeline $global:endTime "dcdiff" "end" "End of capture"

#CSV from timeline
$timelineFile = Join-Path $resultFolder $timelineFilename
$timelineFileHtml = Join-Path $resultFolder $timelineFilenameHtml
Add-Content -Path $timelineFile  -Value '"Time","Source","Event"'
$global:timeline | Sort-Object time | Export-Csv -Path $timelineFile #Select-Object -Property time, source, event | 

#HTML timeline
$prec = "<h1>Timeline/Events</h1>Contains events from EVTX and other sources when a timestamp is provided (NTDS/UAL). You will find the corresponding EVTX files in the results folder."
$timelineString = $global:timeline | Sort-Object time | ConvertTo-Html -Head "$header" -PreContent $prec
$timelineString.replace("dcdiff","<font color='#ff0000'>dcdiff</font>") | Out-File $timelineFileHtml
