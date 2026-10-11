#Requires -Version 5.1
<#
.SYNOPSIS
    WindowsAudit — Outil d'audit de sécurité Windows aligné ANSSI BP-028.

.DESCRIPTION
    Effectue un diagnostic de la posture sécurité d'un poste Windows.
    Génère un rapport HTML et/ou JSON dans le dossier de sortie.

.PARAMETER Level
    Niveau de vérification : N1 (Fondamentaux), N1N2 (+ Intermédiaire), All (complet).
    Exclusif avec -Module.

.PARAMETER Module
    Exécute un seul module : IAM, Patches, Network, Logs, Workstation, ASR, WDAC.
    Exclusif avec -Level.

.PARAMETER ReportName
    Nom du fichier de rapport (sans extension). Par défaut : WindowsAudit_<hôte>_<horodatage>.

.PARAMETER OutputPath
    Dossier de sortie des rapports. Par défaut : .\Output.

.PARAMETER ReportFormat
    Format du rapport : HTML, JSON, ou All (les deux). Par défaut : HTML.

.EXAMPLE
    .\WindowsAudit.ps1 -Level N1
    .\WindowsAudit.ps1 -Level All -ReportFormat All
    .\WindowsAudit.ps1 -Module IAM -ReportFormat JSON
#>

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

# ---------------------------------------------------------------------------
# INITIALISATION
# ---------------------------------------------------------------------------

$RootPath  = $PSScriptRoot
Add-Type -AssemblyName System.Security
$startTime = Get-Date

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        WindowsAudit v1.0 — ANSSI BP-028      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Chargement des composants
$components = @(
    "Core\ParameterHandler.ps1",
    "Core\AuditContext.ps1",
    "Core\Orchestrator.ps1",
    "Renderers\HtmlRenderer.ps1",
    "Renderers\JsonRenderer.ps1"
)

foreach ($component in $components) {
    $componentPath = Join-Path $RootPath $component
    if (-not (Test-Path $componentPath)) {
        Write-Error "Composant manquant : $componentPath"
        exit 1
    }
    . $componentPath
    Write-Verbose "[WindowsAudit] Composant chargé : $component"
}

# ---------------------------------------------------------------------------
# EXÉCUTION
# ---------------------------------------------------------------------------

# 1. Paramètres
Write-Host "[1/4] Validation des paramètres..." -ForegroundColor Gray
$handlerArgs =@{}
if ($Level) {$handlerArgs['Level']  = $Level}
if ($Module) {$handlerArgs['Module']  = $Module}
if ($ReportName) {$handlerArgs['ReportName']  = $ReportName}
if ($OutputPath) {$handlerArgs['OutputPath']  = $OutputPath}
if ($OutputPath) {$handlerArgs['ReportFormat']  = $ReportFormat}

$auditParams = Invoke-ParameterHandler @handlerArgs

# 2. Contexte poste
Write-Host "[2/4] Collecte du contexte poste..." -ForegroundColor Gray
$auditContext = Invoke-AuditContext

Write-Host "      Hôte    : $($auditContext.Hostname)" -ForegroundColor Gray
Write-Host "      OS      : $($auditContext.OsVersion)" -ForegroundColor Gray
Write-Host "      Admin   : $(if ($auditContext.IsAdmin) { 'Oui' } else { 'Non' })" -ForegroundColor Gray
Write-Host ""

# 3. Audit
Write-Host "[3/4] Exécution de l'audit (niveau : $($auditParams.Level)$($auditParams.Module))..." -ForegroundColor Gray
$auditReport = Invoke-Orchestrator `
    -AuditParameters $auditParams `
    -AuditContext    $auditContext `
    -RootPath        $RootPath `
    -Verbose:($VerbosePreference -eq 'Continue')

# 4. Génération des rapports
Write-Host "[4/4] Génération du rapport..." -ForegroundColor Gray
$generatedFiles = @()

if ($auditParams.ReportFormat -eq "HTML" -or $auditParams.ReportFormat -eq "All") {
    $htmlFile = Invoke-HtmlRenderer `
        -AuditReport $auditReport `
        -OutputPath  $auditParams.OutputPath `
        -ReportName  $auditParams.ReportName
    $generatedFiles += $htmlFile
    Write-Host "      HTML : $htmlFile" -ForegroundColor Gray
}

if ($auditParams.ReportFormat -eq "JSON" -or $auditParams.ReportFormat -eq "All") {
    $jsonFile = Invoke-JsonRenderer `
        -AuditReport $auditReport `
        -OutputPath  $auditParams.OutputPath `
        -ReportName  $auditParams.ReportName
    $generatedFiles += $jsonFile
    Write-Host "      JSON : $jsonFile" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# RÉSUMÉ FINAL
# ---------------------------------------------------------------------------

$duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

# Calcul du score global
$allResults  = $auditReport.modules | ForEach-Object { $_.results } | Where-Object { $_ }
$totalPass   = ($allResults | Where-Object { $_.status -eq "pass"   } | Measure-Object).Count
$totalFail   = ($allResults | Where-Object { $_.status -eq "fail"   } | Measure-Object).Count
$totalManual = ($allResults | Where-Object { $_.status -eq "manual" } | Measure-Object).Count
$totalError  = ($allResults | Where-Object { $_.status -eq "error"  } | Measure-Object).Count
$totalScored = $totalPass + $totalFail + $totalError
$scorePct    = if ($totalScored -gt 0) { [math]::Round($totalPass / $totalScored * 100) } else { 0 }

$scoreColor = if ($scorePct -ge 80) { "Green" } elseif ($scorePct -ge 50) { "Yellow" } else { "Red" }

Write-Host ""
Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Résultat de l'audit" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Score global  : " -NoNewline
Write-Host "$scorePct%" -ForegroundColor $scoreColor
Write-Host "  Pass          : $totalPass" -ForegroundColor Green
Write-Host "  Fail          : $totalFail" -ForegroundColor Red
Write-Host "  Manuel        : $totalManual" -ForegroundColor Blue
Write-Host "  Erreur        : $totalError" -ForegroundColor Yellow
Write-Host "  Durée         : ${duration}s"
Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

foreach ($file in $generatedFiles) {
    Write-Host "  Rapport : $file" -ForegroundColor Cyan
}
Write-Host ""

