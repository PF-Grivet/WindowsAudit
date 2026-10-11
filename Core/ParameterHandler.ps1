function Invoke-ParameterHandler {
    [CmdletBinding()]
    param (
        [ValidateSet("N1", "N1N2", "All")]
        [string]$level,

        [ValidateSet("IAM", "Patches", "Network", "Logs", "Workstation", "ASR", "WDAC")]
        [string]$Module,

        [string]$ReportName,

        [string]$OutputPath,

        [ValidateSet("HTML", "JSON", "All")]
        [string]$ReportFormat
    )
    
    # --- Detection appel sans paramètres ---
    $noParams = (-not $Level) -and (-not $Module) -and (-not $ReportName) -and (-not $OutputPath) -and (-not $ReportFormat)

    if ($noParams) {
        Write-Host "[WindowsAudit] Aucun paramètre fourni. Defaults appliqués : Level=N1, ReportFormat=HTML, OutPath=.\Output\" -ForegroundColor Yellow
        $Level = "N1"
        $ReportFormat = "HTML"
        $OutputPath = ".\Output"
    }

    Write-Verbose "[ParameterHandler] Début de la validation des paramètres."

    # --- Conflit Level + Module ---
    if ($level -and $Module) {
        throw "[WindowsAudit] les paramètres -Level et -Module sont mutuellement exclusifs. " + 
            "Utilisez -Level pour auditer un périmètre par maturité, ou -Module pour cibler un module spécifique."
    }

    Write-Verbose "[ParameterHandler] Validation Level/Module : OK."

    # --- Defaut individuels ---
    if (-not $Level -and -not $Module) {
        $Level = "N1"
        Write-Verbose "[ParamaeterHandler] Level non fourni, defaut appliqué : N1."
    }

    if (-not $ReportFormat) {
        $ReportFormat = "HTML"
        Write-Verbose "[ParameterHandler] ReportFormat non fourni, defaut appliqué : HTML."
    }

    if (-not $OutputPath) {
        $OutputPath = ".\Output"
        Write-Verbose "[ParameterHandler] Output Path non fourni, defaut appliqué: .\Output."
    }

    #--- Création OutputPath si inexistant ---
    if (-not (Test-Path -Path $OutputPath)) {
        Write-Verbose "[ParameterHandler] OutputPath '$OutputPath' inexistant, création en cours."
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force| Out-Null
            Write-Verbose "[ParameterHandler] OutputPath crée : $OutputPath"
        }
        catch {
            throw "[WindowsAudit] Impossible de créer le répertoir de sortie '$OutputPath' : $_"
        }
    }
    else {
        Write-Verbose "[ParameterHandler] OutputPath '$OutputPath' existe déjà"
    }

    # --- Génération ReportName par défaut ----------
    if (-not $ReportName) {
        $hostname = $env:COMPUTERNAME
        $timestamp = Get-Date -Format "yyyMMdd-HHmm"
        $ReportName = "WindowsAudit_${hostname}_${timestamp}"
        Write-Verbose "[ParameterHandler] ReportName généré : $ReportName."
    }
    else {
        Write-Verbose "[ParameterHandler] ReportName fourni : $ReportName."
    }

    #--- Constructuion de l'objet de sortie
    $result = [PSCustomObject]@{
        Level = $Level
        Module = $Module
        ReportName = $ReportName
        OutputPath = $OutputPath
        ReportFormat = $ReportFormat
    }

    Write-Verbose "[ParameterHandler] Paramètres validés et finalisés."
    Write-Verbose "[ParameterHandler] Level=$($result.Level) | Module=$($result.Module) | ReportFormat=$($result.ReportFormat)"
    Write-Verbose "[ParameterHandler] ReportName=$($result.ReportName)"
    Write-Verbose "[ParameterHandler] OutputPatch=$($result.OutputPath)"

    return $result
}