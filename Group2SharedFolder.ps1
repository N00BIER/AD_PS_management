param(
    [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()] [string] $Client,
    [Parameter(Mandatory=$true, Position=1)][ValidateNotNullOrEmpty()] [string] $Matter
    )

$Domain = "xyz.local"
$ADPath = "OU=Access Rights,DC=XYZ,DC=LOCAL"
$ClientPath = "C:\Users\$Client"
$MatterPath = "C:\Users\$Client\$Matter"


# Adding the AD groups
New-ADGroup `
    -Name $("$Client"+"RW") `
    -SamAccountName $("$Client"+"RW") `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "$Client Read-Write Access" `
    -Path $ADPath `
    -Description "Members of this group have read-write access"

New-ADGroup `
    -Name $("$Client"+"R") `
    -SamAccountName $("$Client"+"R") `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "$Client Read Access" `
    -Path $ADPath `
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
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$($Client+"R")","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$($Client+"RW")","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client"

# Create new folder
New-Item -Path $MatterPath -ItemType Directory

# Get permissions
$acl = Get-Acl -Path $MatterPath

# Get Security Groups
get-adobject -searchbase $ADPath -ldapfilter {(objectclass=group)}

# Add a new permission
$acl.SetAccessRuleProtection($True, $False)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client\$Matter"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client\$Matter"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$($Client+"R")","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client\$Matter"

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$($Client+"RW")","Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule) | set-acl "\\DC-1\Users\$Client\$Matter"
