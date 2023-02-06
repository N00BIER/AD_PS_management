$secgroups=@("Enterprise admins","Schema admins","Domain admins","Account operators","Server operators","Print operators","DHCP Administrators","DNSAdmins")

foreach ($group in $secgroups){

Get-AdGroupMember -Identity $group | where {$_.objectclass -eq 'user'} | get-ADUser -Properties LastLogonDate | select name,lastlogondate

}