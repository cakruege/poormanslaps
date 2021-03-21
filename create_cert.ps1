$certinf = @'
[Version]
Signature = "$Windows NT$"

[Strings]
szOID_ENHANCED_KEY_USAGE = "2.5.29.37"
szOID_DOCUMENT_ENCRYPTION = "1.3.6.1.4.1.311.80.1"

[NewRequest]
Subject = "cn=adminpasswords"
MachineKeySet = true
KeyLength = 4096
KeySpec = AT_KEYEXCHANGE
HashAlgorithm = Sha256
Exportable = true
RequestType = Cert

KeyUsage = "CERT_KEY_ENCIPHERMENT_KEY_USAGE | CERT_DATA_ENCIPHERMENT_KEY_USAGE"
ValidityPeriod = "Years"
ValidityPeriodUnits = "10"

[Extensions]
%szOID_ENHANCED_KEY_USAGE% = "{text}%szOID_DOCUMENT_ENCRYPTION%"
'@

set-content -value $certinf -Path adminpasswords.inf
certreq -new 'adminpasswords.inf' 'adminpasswords.cer'