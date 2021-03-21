Set-StrictMode -Version 2.0

# https://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
# AD Password complexity requirements

# ~ 6.5 Bits of entropy per character
[String[]]$CharGroups = @('abcdefghijkmnopqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '0123456789', '~!@#$%^&*_-+=`|\(){}[]:;"''<>,.?/')
$AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

# recommendation: at least 15 characters because of LMhashes
# https://support.microsoft.com/en-us/help/299656/how-to-prevent-windows-from-storing-a-lan-manager-hash-of-your-password-in-active-directory-and-local-sam-databases

# https://gallery.technet.microsoft.com/scriptcenter/Verify-password-complexity-c9e6f42f
Function Test-PasswordIsComplex{
[OutputType([boolean])] 
Param 
( 
    [Parameter(Mandatory=$true)]
    [String]$pw2test
)
    $isGood = 0
    If ($pw2test -match "[^a-zA-Z0-9]") #check for special chars
    	{ $isGood++ }
    If ($pw2test -match "[0-9]")
    	{ $isGood++ }
    If ($pw2test -cmatch "[a-z]")
    	{ $isGood++ }
    If ($pw2test -cmatch "[A-Z]")
    	{ $isGood++ }
    If ($isGood -eq 4)
    	{ return $true }
    else
        { return $false }
}


Function New-ComplexPassword
{
[OutputType([String])] 
param(
    [Parameter(Mandatory=$false)]
    [int]$PasswordLength = 16
)
    $RandomBytes = New-Object -TypeName 'System.Byte[]' $PasswordLength
    $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider' # cryptographic secure random
    do {
        $Random.GetBytes($RandomBytes)
        $Password=""
        for ($i=0; $i -lt $PasswordLength; $i++) 
        {
            $Password+=$AllChars[$RandomBytes[$i] % $AllChars.Length]
        }  
    } until (Test-PasswordIsComplex -pw2test $Password)
    return $Password    
}