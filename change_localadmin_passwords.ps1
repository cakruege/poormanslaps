#requires -Version 5.1
. .\Get-LocalUsersThatAreMemberOfLocalAdminstrators.ps1
. .\New-ComplexPassword.ps1
# .\write-only-once-fileshare.ps1

$pathToFileShare="\\192.168.3.100\acltest" # must be a write once file share!

$admins=Get-LocalUsersThatAreMemberOfLocalAdminstrators

$users=@()
foreach ($admin in $admins)
{
  $user = New-Object System.Object
  $user | Add-Member -type NoteProperty -name Name -value $admin
  $user | Add-Member -type NoteProperty -name Password -value (New-ComplexPassword)
  $users+=$user
}

 $computername=get-content env:computername
 $filename=$computername+'_'+(Get-Date -f 'yyyyMMddHHmmss')+'.txt'

 $fullpath=join-path $pathToFileShare $filename
 try {
   $message=Out-String -InputObject $users
   $protecedmessage=Protect-CmsMessage -To .\adminpasswords.cer -Content $message
   set-content -path $fullpath -Value $protecedmessage
 } catch
 {
   Write-Output "could not write password"
   break
 }     
 foreach ($user in $users)
 {
    $user.Password
    $SecurePassword = $user.Password | ConvertTo-SecureString -AsPlainText -Force
    Get-localuser $user.Name | set-LocalUser -password $SecurePassword
 }

