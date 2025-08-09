<# 
.SYNOPSIS
Crear usuarios de AD desde JSON o generarlos dinámicamente para un lab.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
  # --- Modo JSON ---
  [Parameter(ParameterSetName="json", Mandatory=$true)]
  [string] $JSONFile,

  # --- Modo Generador ---
  [Parameter(ParameterSetName="gen", Mandatory=$true)]
  [int] $Count,

  [Parameter(ParameterSetName="gen", Mandatory=$true)]
  [string] $Domain,

  # --- Comunes ---
  [string] $OU,                                # ahora usable en ambos modos
  [string[]] $GroupNames,                      # opcional; si no se pasa, usa data\groupNames.txt
  [switch] $CreateMissingGroups,
  [switch] $WhatIf,
  [string] $OutputCsv = ".\created-users-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

# Init CSV (encabezado simple)
if (-not (Test-Path $OutputCsv)) {
  "Name,SamAccountName,UPN,DistinguishedName,TempPassword,Groups" | Out-File -Encoding UTF8 $OutputCsv
}

# ---- Pools basados en archivos ------------------------------------------------
# Carpeta de datos junto al script
$dataDir    = Join-Path $PSScriptRoot 'data'
$groupsFile = Join-Path $dataDir 'groupNames.txt'

function Get-RandomGroups {
  param(
    [string[]] $Pool,
    [int] $Min = 1,
    [int] $Max = 3
  )
  if (-not $Pool -or $Pool.Count -eq 0) { return @() }
  $cap = [Math]::Min($Max, $Pool.Count)
  $n   = Get-Random -Minimum $Min -Maximum ($cap + 1)
  if ($n -lt $Min) { $n = $Min }
  $Pool | Get-Random -Count $n
}

# Cargar grupos desde data\groupNames.txt si existe
if (Test-Path $groupsFile) {
  $fileGroups = Get-Content $groupsFile | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }
} else {
  $fileGroups = @()
}

# ---- Helpers -----------------------------------------------------------------
function Ensure-ADGroup {
  param(
    [Parameter(Mandatory=$true)][string] $Name,
    [string] $Description = "Lab group"
  )
  $g = Get-ADGroup -LDAPFilter "(cn=$Name)" -ErrorAction SilentlyContinue
  if (-not $g) {
    if ($CreateMissingGroups) {
      Write-Verbose "Creating missing group: $Name"
      try {
        New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security `
          -Description $Description -Path $OU -WhatIf:$WhatIf -ErrorAction Stop | Out-Null
        $g = Get-ADGroup -LDAPFilter "(cn=$Name)" -ErrorAction SilentlyContinue
      } catch {
        Write-Warning "Failed to create group '$Name': $($_.Exception.Message)"
      }
    } else {
      Write-Warning "Group '$Name' not found and -CreateMissingGroups not set. Skipping adds."
    }
  }
  return $g
}

function New-RandomPassword {
  param([int]$Length=14)
  $lower = -join ((97..122) | Get-Random -Count 3 | ForEach-Object {[char]$_})
  $upper = -join ((65..90)  | Get-Random -Count 3 | ForEach-Object {[char]$_})
  $digit = -join ((48..57)  | Get-Random -Count 3 | ForEach-Object {[char]$_})
  $symbs = '!@#$%_-+='
  $sym   = -join (1..3 | ForEach-Object { $symbs[(Get-Random -Min 0 -Max $symbs.Length)] })
  $restLen = [Math]::Max(0, $Length - ($lower+$upper+$digit+$sym).Length)
  $all = (@((97..122)+(65..90)+(48..57)+[char[]]$symbs) | ForEach-Object {[char]$_})
  $rest = -join (1..$restLen | ForEach-Object { $all | Get-Random })
  (-join ($lower+$upper+$digit+$sym+$rest).ToCharArray() | Sort-Object {Get-Random}) -replace '\s',''
}

# Pools de nombres (puedes migrarlos a data\ si querés)
$FirstNames = @(
  'Alice','Bob','Carol','David','Eve','Frank','Grace','Heidi','Ivan','Judy',
  'Kathy','Leo','Mallory','Niaj','Olivia','Peggy','Quinn','Ruth','Sybil','Trent',
  'Uma','Victor','Wendy','Xavier','Yara','Zane'
)
$LastNames = @(
  'Morgan','Stone','Reed','Clark','Fisher','Barnes','Young','Hayes','Carter','Diaz',
  'Nguyen','Lopez','King','Brooks','Price','Wells','Hughes','Baker','Cole','Shaw'
)

function New-RandomUserObject {
  param([string[]]$PossibleGroups,[string]$Domain)
  $fn = $FirstNames | Get-Random
  $ln = $LastNames  | Get-Random
  $name = "$fn $ln"
  $pass = New-RandomPassword
  $username = ("{0}{1}" -f $fn.Substring(0,1), $ln).ToLower()
  $email = "$username@$Domain"
  $depts = @("IT","HR","Finance","Sales","Marketing","Ops")
  $titles = @("Analyst","Engineer","Specialist","Coordinator","Manager")
  $grpCount = if ($PossibleGroups.Count -gt 0) { Get-Random -Minimum 1 -Maximum ([Math]::Min(3,$PossibleGroups.Count)+1) } else { 0 }
  $grps = if ($grpCount -gt 0) { $PossibleGroups | Get-Random -Count $grpCount } else { @() }
  [pscustomobject]@{
    Name       = $name
    Password   = $pass
    Email      = $email
    Department = $depts | Get-Random
    Title      = "$($titles | Get-Random)"
    Groups     = $grps
  }
}

function Get-UniqueSamAndUpn {
  param(
    [Parameter(Mandatory)][string] $BaseSam,
    [Parameter(Mandatory)][string] $Domain
  )
  $sam = $BaseSam
  $i = 1
  while ($null -ne (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
    $i++
    $sam = "{0}{1}" -f $BaseSam, $i
  }
  $upn = "$sam@$Domain"
  while ($null -ne (Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -ErrorAction SilentlyContinue)) {
    $i++
    $sam = "{0}{1}" -f $BaseSam, $i
    $upn = "$sam@$Domain"
  }
  [pscustomobject]@{ Sam = $sam; UPN = $upn }
}

function Create-ADUser {
  param(
    [Parameter(Mandatory)] $UserObject,
    [Parameter(Mandatory)] [string] $Domain,
    [string] $OU
  )
  try {
    $name     = $UserObject.Name
    $password = $UserObject.Password
    $groups   = $UserObject.Groups
    $email    = $UserObject.Email
    $dept     = $UserObject.Department
    $title    = $UserObject.Title

    if (-not $name)     { throw "UserObject.Name missing" }
    if (-not $password) { throw "UserObject.Password missing" }

    $firstname, $lastname = $name.Split(" ",2)
    if (-not $lastname) { $lastname = $firstname; $firstname = $name }

    $baseSam        = ("{0}{1}" -f $firstname.Substring(0,1), $lastname).ToLower()
    $unique         = Get-UniqueSamAndUpn -BaseSam $baseSam -Domain $Domain
    $samAccountName = $unique.Sam
    $upn            = $unique.UPN
    $secure         = ConvertTo-SecureString $password -AsPlainText -Force

    $newUser = New-ADUser `
      -Name $name `
      -GivenName $firstname `
      -Surname $lastname `
      -SamAccountName $samAccountName `
      -UserPrincipalName $upn `
      -AccountPassword $secure `
      -Enabled $true `
      -ChangePasswordAtLogon $true `
      -EmailAddress $email `
      -Department $dept `
      -Title $title `
      -Path $OU `
      -PassThru `
      -WhatIf:$WhatIf `
      -ErrorAction Stop

    # Membresías de grupo
    if ($groups) {
      foreach ($g in $groups) {
        $groupName = if ($g -is [string]) { $g } else { $g.Name }
        if ([string]::IsNullOrWhiteSpace($groupName)) { continue }
        $adGroup = Ensure-ADGroup -Name $groupName
        if ($adGroup) {
          try {
            Add-ADGroupMember -Identity $adGroup.DistinguishedName `
                              -Members  $samAccountName `
                              -WhatIf:$WhatIf `
                              -ErrorAction Stop
          } catch {
            if ($_.Exception.Message -match 'already a member') {
              Write-Verbose "$samAccountName already in ${groupName}"
            } else {
              Write-Warning "Failed to add $samAccountName to ${groupName}: $($_.Exception.Message)"
            }
          }
        } else {
          Write-Warning "Group '${groupName}' not found/created; skipping for $samAccountName."
        }
      }
    }

    # Log CSV
    $dn = if ($newUser) { $newUser.DistinguishedName } else { "" }
    $grpText = ($groups | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.Name } }) -join ';'
    $line = '"{0}","{1}","{2}","{3}","{4}","{5}"' -f `
            $name, $samAccountName, $upn, $dn, $password, $grpText
    Add-Content -Encoding UTF8 -Path $OutputCsv -Value $line

    Write-Host "[OK] $name ($upn)" -ForegroundColor Green
  } catch {
    Write-Host "[ERR] $name :: $($_.Exception.Message)" -ForegroundColor Red
  }
}

# ===== Modo JSON ==============================================================
if ($PSCmdlet.ParameterSetName -eq "json") {
  $json   = Get-Content -Raw $JSONFile | ConvertFrom-Json
  $domain = $json.domain
  if (-not $domain) { throw "JSON missing 'domain' field" }

  # OU: del JSON o default a OU=Lab Users,<DN del dominio>
  if ($json.ou) { 
    $OU = $json.ou 
  } elseif (-not $OU) {
    $OU = "OU=Lab Users,$((Get-ADDomain).DistinguishedName)"
  }

  # Crear grupos del JSON si existen
  if ($CreateMissingGroups -and $json.groups) {
    foreach ($g in $json.groups) {
      if ($g -is [string]) { $name = $g; $desc = 'Lab group' }
      else {
        $name = $g.Name
        $desc = $g.Description
        if ([string]::IsNullOrWhiteSpace($desc)) { $desc = 'Lab group' }
      }
      if ([string]::IsNullOrWhiteSpace($name)) { Write-Warning "Skipping a group with no name."; continue }
      Ensure-ADGroup -Name $name -Description $desc | Out-Null
    }
  }
  # Si el JSON no define groups a nivel raíz y tenemos archivo, pre-crear esos también
  if ($CreateMissingGroups -and (-not $json.groups) -and $fileGroups.Count -gt 0) {
    foreach ($g in $fileGroups) { Ensure-ADGroup -Name $g | Out-Null }
  }

  foreach ($u in $json.users) {
    $userObject = @{
      Name       = $u.name
      Password   = $u.password
      Email      = $u.email
      Department = $u.department
      Title      = $u.title
      Groups     = $u.groups
    }

    # Si este usuario no trae grupos → asignar aleatorios desde archivo/fallback
    if (-not $userObject.Groups -or $userObject.Groups.Count -eq 0) {
      $pool = if ($fileGroups.Count -gt 0) { $fileGroups } else { @('IT','HR','Finance','Sales') }
      $userObject.Groups = Get-RandomGroups -Pool $pool -Min 1 -Max ([Math]::Min(3, $pool.Count))
    }

    Create-ADUser -UserObject $userObject -Domain $domain -OU $OU
  }
  return
}

# ===== Modo Generador =========================================================
# Domain/OU por defecto si faltan (solo por seguridad)
if (-not $OU) { $OU = "OU=Lab Users,$((Get-ADDomain).DistinguishedName)" }

# Si no pasaron -GroupNames, usar archivo o fallback
if (-not $GroupNames -or $GroupNames.Count -eq 0) {
  $GroupNames = if ($fileGroups.Count -gt 0) { $fileGroups } else { @('IT','HR','Finance','Sales') }
}

# Pre-crear grupos si se pidió
if ($CreateMissingGroups -and $GroupNames.Count -gt 0) {
  foreach ($g in $GroupNames) { Ensure-ADGroup -Name $g | Out-Null }
}

1..$Count | ForEach-Object {
  $u = New-RandomUserObject -PossibleGroups $GroupNames -Domain $Domain
  Create-ADUser -UserObject $u -Domain $Domain -OU $OU
}
