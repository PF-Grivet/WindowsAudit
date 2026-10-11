function Invoke-AuditContext {
    [CmdletBinding()]
    param()

    Add-Type -AssemblyName System.Security

    Write-Verbose "[AuditContext] Début de la collecte du context poste."

    #--- Hostname ---
    $hostname =$env:COMPUTERNAME
    Write-Verbose "[AuditContext] Hostname : $hostname"

    # --- Version OS --
    try {
        $osInfo =Get-CimInstance Win32_OperatingSystem
        $osVersion = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
        Write-Verbose "[AuditContexte] OS : $osVersion."
    }
    catch {
        Write-Warning "[WindowsAudit] Impossible de récupérer la version OS : $_"
        $osVersion = "Inconnu"
    }

    # --- Domaine ---
    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain
        Write-Verbose "[AuditContext] Join au domaine : $isDomainJoined"
    }
    catch {
        Write-Warning "[WindowsAudit] Impossible de déterminer l'appartenance au domaine : $_"
        $isDomainJoined = $false
    }

    # --- Droits Admin ---
    try {
        $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Verbose "[AuditContext] Droits administrateur : $isAdmin."
    }
    catch {
        Write-Warning "[WindowsAuidt] Impossible de déterminer les droits administrateur :$_"
        $isAdmin = $false
    }

    #---- TimeStamp ---
    $auditTimestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    Write-Verbose "[AuditContext] Timestamp audit : $auditTimestamp."

    # --- Construction de l'objet de sortie
    $context = [PSCustomObject]@{
        Hostname = $hostname
        OsVersion = $osVersion
        IsDomaninJoined = $isDomainJoined
        IsAdmin = $isAdmin
        AuditTimestamp =$auditTimestamp
    }

    Write-Verbose "[AuditContext] Contexte collecté avec succés."
    return $context
}