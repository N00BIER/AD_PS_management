## Report for DC login failures ##
param(
    [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()] [string] $cname
)

$failedevent=Get-Eventlog security -computer $cname -InstanceID 4625 -after (Get-date).AddDays(-7) | 
select TimeGenerated,ReplacementStrings |
% {
  New-Object PSObject -Property @{
  SourceComputer=$_.ReplacementStrings[13]
  UserName=$_.ReplacementStrings[5]
  SourceIPaddress=$_.ReplacementStrings[19]
  Date=$_.TimeGenerated
} 
} 
$failedevent | select -property SourceComputer,UserName,SourceIPaddress,Date | ft