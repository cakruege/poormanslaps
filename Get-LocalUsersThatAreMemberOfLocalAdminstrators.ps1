#requires -Version 5.1
Function Get-LocalUsersThatAreMemberOfLocalAdminstrators
{
	# get translated names for WellKnown SIDS
	# for example on a german machine the administrators group is "Administratoren" and the objectclass for users is "Benutzer"
	
	$builtinAdministratorsName=[String]((New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)).Translate([Security.Principal.NTAccount]).Value).Split('\')[1]
	$users=Get-LocalUser | where {$_.Enabled -eq $true}

	[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US';$admins=Get-LocalGroupMember $builtinAdministratorsName | where {$_.ObjectClass -eq 'user'}
	$computername=get-content env:computername
	$localAdminAccounts=@()
	foreach ($user in $users)
	{
	  if ($admins.Name -contains ($computername+'\'+$user))
	  {
		$localAdminAccounts+=$user.Name
	  }
	}
	return $localAdminAccounts
}

