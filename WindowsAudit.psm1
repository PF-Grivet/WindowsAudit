# WindowsAudit.psm1 — Chargement du module

$script:AuditRoot = $PSScriptRoot

# Chargement de tous les composants
$components = @(
    "Core\ParameterHandler.ps1",
    "Core\AuditContext.ps1",
    "Core\Orchestrator.ps1",
    "Renderers\HtmlRenderer.ps1",
    "Renderers\JsonRenderer.ps1",
    "Modules\IAM.ps1",
    "Modules\Patches.ps1",
    "Modules\Network.ps1",
    "Modules\Logs.ps1",
    "Modules\Workstation.ps1",
    "Modules\ASR.ps1",
    "Modules\WDAC.ps1"
)

foreach ($component in $components) {
    $componentPath = Join-Path $script:AuditRoot $component
    if (Test-Path $componentPath) {
        . $componentPath
    } else {
        Write-Warning "[WindowsAudit] Composant manquant : $componentPath"
    }
}

# Fonction publique exportée
function Start-WindowsAudit {
    [CmdletBinding()]
    param(
        [ValidateSet("N1", "N1N2", "All")]
        [string]$Level,

        [ValidateSet("IAM", "Patches", "Network", "Logs", "Workstation", "ASR", "WDAC")]
        [string]$Module,

        [string]$ReportName,
        [string]$OutputPath,

        [ValidateSet("HTML", "JSON", "All")]
        [string]$ReportFormat
    )

    # Paramètres
    $handlerArgs = @{}
    if ($Level)        { $handlerArgs['Level']        = $Level }
    if ($Module)       { $handlerArgs['Module']       = $Module }
    if ($ReportName)   { $handlerArgs['ReportName']   = $ReportName }
    if ($OutputPath)   { $handlerArgs['OutputPath']   = $OutputPath }
    if ($ReportFormat) { $handlerArgs['ReportFormat'] = $ReportFormat }

    $auditParams  = Invoke-ParameterHandler @handlerArgs
    $auditContext = Invoke-AuditContext
    $auditReport  = Invoke-Orchestrator `
        -AuditParameters $auditParams `
        -AuditContext    $auditContext `
        -RootPath        $script:AuditRoot `
        -Verbose:($VerbosePreference -eq 'Continue')

    $generatedFiles = @()

    if ($auditParams.ReportFormat -eq "HTML" -or $auditParams.ReportFormat -eq "All") {
        $generatedFiles += Invoke-HtmlRenderer `
            -AuditReport $auditReport `
            -OutputPath  $auditParams.OutputPath `
            -ReportName  $auditParams.ReportName
    }

    if ($auditParams.ReportFormat -eq "JSON" -or $auditParams.ReportFormat -eq "All") {
        $generatedFiles += Invoke-JsonRenderer `
            -AuditReport $auditReport `
            -OutputPath  $auditParams.OutputPath `
            -ReportName  $auditParams.ReportName
    }

    return [PSCustomObject]@{
        Report = $auditReport
        Files  = $generatedFiles
    }
}

Export-ModuleMember -Function Start-WindowsAudit

