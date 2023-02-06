param(
    [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()] [string] $Client,
    [Parameter(Mandatory=$true, Position=1)][ValidateNotNullOrEmpty()] [string] $Matter,
    )

$Domain = "xyz.local"
$ADPath = "OU=Access Rights,DC=XYZ,DC=LOCAL"
$ClientPath = "\\Storage\Cases\$Client"
$MatterPath = "\\Storage\Cases\$Client\$Matter"


# Adding the AD groups
New-ADGroup 
    -Name "$Client.$MatterRW" 
    -SamAccountName "$Client.$MatterRW" 
    -GroupCategory Security 
    -GroupScope Global 
    -DisplayName "$Client.$Matter Read-Write Access" 
    -Path $ADPath 
    -Description "Members of this group have read-write access"

New-ADGroup 
    -Name "$Client.$MatterR" 
    -SamAccountName "$Client.$MatterR" 
    -GroupCategory Security 
    -GroupScope Global 
    -DisplayName "$Client.$Matter Read Access" 
    -Path $ADPath
    -Description "Members of this group have read access"


# Create new folder
New-Item -Path $ClientPath -ItemType Directory

# Get permissions
$acl = Get-Acl -Path $ClientPath

# Get Security Groups
get-adobject -searchbase $ADPath -ldapfilter {(objectclass=group)}

# Add a new permission
$acl.SetAccessRuleProtection($True, $False)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Litigation Support Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Litigation Support Service","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$Client.$MatterR","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$Client.$MatterRW","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

# set new permissions
$acl | Set-Acl -Path $ClientPath

# Create new folder
New-Item -Path $MatterPath -ItemType Directory

# Get permissions
$acl = Get-Acl -Path $MatterPath

# Get Security Groups
get-adobject -searchbase $ADPath -ldapfilter {(objectclass=group)}

# Add a new permission
$acl.SetAccessRuleProtection($True, $False)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Litigation Support Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Litigation Support Service","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$Client.$MatterR","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$Client.$MatterRW","Modfiy", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

# set new permissions
$acl | Set-Acl -Path $MatterPath