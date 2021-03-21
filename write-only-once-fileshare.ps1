Set-Strictmode -version 2.0
#Requires –Version 3 

# List WellKnownSids
# [Enum]::GetNames([Security.Principal.WellKnownSidType])
# Translate WellKnownSids
#[Enum]::GetNames([Security.Principal.WellKnownSidType]) | % {
#	try{ (New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::$_, $null)).Translate([Security.Principal.NTAccount]).Value } catch {}
#}

# test with sysinternals psexec - https://technet.microsoft.com/en-us/sysinternals
# as user local system (Domain Computer) try to copy a file to the share, it should work
# but only once
# psexec -i -s cmd.exe
# echo test > test.txt
# copy test.txt \\fileshare\acltest
# 1 file(s) copied.
# copy test.txt \\fileshare\acltest
# Access is denied.
# 0 file(s) copied.

$writeOnlyAccount="Domain Computers"  # Domain Users is a bad idea, because every user is member of Domain Users, so the Administrator who should be able to read the files
                                      # other groups not including the ReadWriteAccount are fine
$ReadWriteAccount="Domain Admins" 
$writeOnlyAccount=New-Object System.Security.Principal.NTAccount($writeOnlyAccount) 
$ReadWriteAccount=New-Object System.Security.Principal.NTAccount($ReadWriteAccount) 

$everyone= New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::WorldSid, $null)
$everyoneStr=$everyone.Translate([Security.Principal.NTAccount]).Value

$folder = "c:\temp\acltest"
mkdir $folder -ErrorAction SilentlyContinue

New-SmbShare -Name "acltest" -path $folder –FullAccess $everyoneStr

$objACL = New-Object System.Security.AccessControl.DirectorySecurity # empty ACL

$colRights = [System.Security.AccessControl.FileSystemRights]"DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership"  # full control
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly 
$objType =[System.Security.AccessControl.AccessControlType]::Deny 
$objUser = $writeOnlyAccount 
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL.AddAccessRule($objACE) 

$colRights = [System.Security.AccessControl.FileSystemRights]"ReadData, CreateFiles, Synchronize" 
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$objType =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser = $writeOnlyAccount 
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL.AddAccessRule($objACE) 

$colRights = [System.Security.AccessControl.FileSystemRights]"FullControl" 
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$objType =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser = $ReadWriteAccount
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL.AddAccessRule($objACE) 

$isProtectedFromInheritance=$true
$preserveInheritance=$false
$objACL.SetAccessRuleProtection($isProtectedFromInheritance,$preserveInheritance)

$objUser = $ReadWriteAccount
$objACL.SetOwner($objUser)

$everyone= New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::WorldSid, $null)
$colRights = [System.Security.AccessControl.FileSystemRights]"DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership" 
$AuditFlag = [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$objACE = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone,$colRights,$InheritanceFlag,$PropagationFlag,$AuditFlag)
$objACL.SetAuditRule($objACE) 

Set-ACL $folder $objACL

$acl=Get-ACL $folder -audit # without audit parameter you only get access ACLs
$acl.Owner
$acl.access
$acl.audit
