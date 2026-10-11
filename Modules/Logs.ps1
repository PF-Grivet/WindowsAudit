function Invoke-Logs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[Logs] Démarrage du module Logs."

    $results = @()

    # --- LOG-01a : Journal Security actif ---
    if (-not $AuditContext.IsAdmin) {
        $results += [PSCustomObject]@{
            id             = "LOG-01a"
            level          = "N2"
            severity       = "Critique"
            status         = "manual"
            value          = "Lecture du journal Security nécessite des droits administrateur. Relancer l'audit en élevé pour ce check."
            recommendation = "Activer le journal d'événements Security — essentiel pour tracer authentifications et accès."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
        Write-Verbose "[Logs] LOG-01a : manual, droits admin requis."
    }
    else {
    try {
        $log = Get-WinEvent -ListLog "Security" -ErrorAction Stop
        $isEnabled = $log.IsEnabled

        $results += [PSCustomObject]@{
            id             = "LOG-01a"
            level          = "N2"
            severity       = "Critique"
            status         = if ($isEnabled) { "pass" } else { "fail" }
            value          = "Journal Security : $(if ($isEnabled) {'activé'} else {'désactivé'}). Taille max : $([math]::Round($log.MaximumSizeInBytes / 1MB)) MB."
            recommendation = "Activer le journal d'événements Security — essentiel pour tracer authentifications et accès."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
        Write-Verbose "[Logs] LOG-01a terminé : activé=$isEnabled."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "LOG-01a"
            level          = "N2"
            severity       = "Critique"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'état du journal Security via Get-WinEvent -ListLog Security."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
    }
    }

    # --- LOG-01b : Journal System actif ---
    try {
        $log = Get-WinEvent -ListLog "System" -ErrorAction Stop
        $isEnabled = $log.IsEnabled

        $results += [PSCustomObject]@{
            id             = "LOG-01b"
            level          = "N2"
            severity       = "Moyen"
            status         = if ($isEnabled) { "pass" } else { "fail" }
            value          = "Journal System : $(if ($isEnabled) {'activé'} else {'désactivé'}). Taille max : $([math]::Round($log.MaximumSizeInBytes / 1MB)) MB."
            recommendation = "Activer le journal d'événements System pour la traçabilité des événements système."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
        Write-Verbose "[Logs] LOG-01b terminé : activé=$isEnabled."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "LOG-01b"
            level          = "N2"
            severity       = "Moyen"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'état du journal System via Get-WinEvent -ListLog System."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
    }

    # --- LOG-01c : Journal Application actif ---
    try {
        $log = Get-WinEvent -ListLog "Application" -ErrorAction Stop
        $isEnabled = $log.IsEnabled

        $results += [PSCustomObject]@{
            id             = "LOG-01c"
            level          = "N2"
            severity       = "Moyen"
            status         = if ($isEnabled) { "pass" } else { "fail" }
            value          = "Journal Application : $(if ($isEnabled) {'activé'} else {'désactivé'}). Taille max : $([math]::Round($log.MaximumSizeInBytes / 1MB)) MB."
            recommendation = "Activer le journal d'événements Application pour la traçabilité des applications."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
        Write-Verbose "[Logs] LOG-01c terminé : activé=$isEnabled."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "LOG-01c"
            level          = "N2"
            severity       = "Moyen"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'état du journal Application via Get-WinEvent -ListLog Application."
            anssi_ref      = "ANSSI-BP-028 R41"
        }
    }

    # --- LOG-02 : Rétention des logs (manuel) ---
    try {
        $journauxAVerifier = if ($AuditContext.IsAdmin) { @("Security", "System", "Application") } else { @("System", "Application") }

        $detail = $journauxAVerifier | ForEach-Object {
            $log = Get-WinEvent -ListLog $_ -ErrorAction Stop
            $mode = if ($log.LogMode) { $log.LogMode } else { "Inconnu" }
            "$_=$([math]::Round($log.MaximumSizeInBytes / 1MB))MB/$mode"
        }

        $noteAdmin = if (-not $AuditContext.IsAdmin) { " (Security exclu : droits administrateur requis)" } else { "" }

        $results += [PSCustomObject]@{
            id             = "LOG-02"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = "Taille et mode de rétention par journal : $($detail -join ' | ')$noteAdmin"
            recommendation = "Définir une politique de rétention des logs adaptée au contexte métier (taille et durée de conservation)."
            anssi_ref      = "ANSSI-BP-028 R42"
        }
        Write-Verbose "[Logs] LOG-02 terminé : $($detail -join ', ')."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "LOG-02"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = "Détection automatique impossible : $($_.ToString())"
            recommendation = "Vérifier manuellement la politique de rétention des journaux d'événements."
            anssi_ref      = "ANSSI-BP-028 R42"
        }
    }

    # --- LOG-03 : Audit policy (logon/logoff de base) ---
    try {
        $auditOutput = auditpol /get /subcategory:"Logon" 2>&1
        $auditOutputLogoff = auditpol /get /subcategory:"Logoff" 2>&1

        $logonConfigured  = $auditOutput      -match "Success" -or $auditOutput      -match "Failure"
        $logoffConfigured = $auditOutputLogoff -match "Success" -or $auditOutputLogoff -match "Failure"

        $status = if ($logonConfigured -and $logoffConfigured) { "pass" } else { "fail" }

        $results += [PSCustomObject]@{
            id             = "LOG-03"
            level          = "N2"
            severity       = "Élevé"
            status         = $status
            value          = "Audit Logon configuré : $logonConfigured | Audit Logoff configuré : $logoffConfigured."
            recommendation = "Activer l'audit des événements de connexion/déconnexion (auditpol /set /subcategory:Logon,Logoff /success:enable /failure:enable)."
            anssi_ref      = "ANSSI-BP-028 R43"
        }
        Write-Verbose "[Logs] LOG-03 terminé : logon=$logonConfigured logoff=$logoffConfigured."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "LOG-03"
            level          = "N2"
            severity       = "Élevé"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement la politique d'audit via auditpol /get /category:*."
            anssi_ref      = "ANSSI-BP-028 R43"
        }
    }

    # --- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module    = [PSCustomObject]@{ name = "Logs"; version = "1.0" }
        execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error = $null }
        results   = $results
    }

    Write-Verbose "[Logs] Module Logs terminé. $($results.Count) vérification(s) effectuée(s)."
    return $moduleResult
}