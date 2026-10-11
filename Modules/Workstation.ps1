function Invoke-Workstation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[Workstation] Démarrage du module Workstation."

    $results = @()

# --- WS-01 : BitLocker (tous volumes fixes) ---
if (-not $AuditContext.IsAdmin) {
    $results += [PSCustomObject]@{
        id = "WS-01"
        level = "N2"
        severity = "Critique"
        status = "manual"
        value = "Lecture de l'état BitLocker nécessite des droits administrateur. Relancer l'audit en élevé pour ce check."
        recommendation = "Activer BitLocker sur tous les volumes fixes (système et données) du poste."
        anssi_ref = "ANSSI-BP-028 R51"
    }
    Write-Verbose "[Workstation] WS-01 : manual, droits admin requis."
}
else {
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq "Data" -or $_.VolumeType -eq "OperatingSystem" }
 
    if (($volumes | Measure-Object).Count -eq 0) {
        $results += [PSCustomObject]@{
            id = "WS-01"
            level = "N2"
            severity = "Critique"
            status = "fail"
            value = "Aucun volume fixe détecté ou BitLocker non disponible."
            recommendation = "Activer BitLocker sur tous les volumes fixes du poste."
            anssi_ref = "ANSSI-BP-028 R51"
        }
    }
    else {
        $detail = $volumes | ForEach-Object { "$($_.MountPoint)=$($_.ProtectionStatus)" }
        $allProtected = -not ($volumes | Where-Object { $_.ProtectionStatus -ne "On" })
 
            $results += [PSCustomObject]@{
                id = "WS-01"
                level = "N2"
                severity = "Critique"
                status = if ($allProtected) { "pass" } else { "fail" }
                value = "État BitLocker par volume : $($detail -join ' | ')"
                recommendation = "Activer BitLocker sur tous les volumes fixes (système et données) du poste."
                anssi_ref = "ANSSI-BP-028 R51"
            }
        }
        Write-Verbose "[Workstation] WS-01 terminé."
    }
    catch {
        $results += [PSCustomObject]@{
            id = "WS-01"
            level = "N2"
            severity = "Critique"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement l'état BitLocker via Get-BitLockerVolume (nécessite potentiellement des droits administrateur)."
            anssi_ref = "ANSSI-BP-028 R51"
            }
    }
    }

    # --- WS-02 : Outil de gestion centralisée (MDM/SCCM) — informatif ---
    try {
        $mdmEnrolled = $false
        $mdmDetail   = "Non détecté"
        try {
            $dsreg = dsregcmd /status 2>&1
            $mdmJoined = $dsreg | Select-String "AzureAdJoined\s*:\s*YES|DomainJoined\s*:\s*YES"
            if ($mdmJoined) {
                $mdmEnrolled = $true
                $mdmDetail = "Entra/AD détecté (dsregcmd)"
            }
        }
        catch { }

        $sccmService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
        $sccmDetected = $null -ne $sccmService

        $valueText = "MDM/Entra : $(if ($mdmEnrolled) {$mdmDetail} else {'non détecté'}) | Agent SCCM (CcmExec) : $(if ($sccmDetected) {'présent'} else {'absent'})"

        $results += [PSCustomObject]@{
            id             = "WS-02"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = $valueText
            recommendation = "Un poste non rattaché à une gestion centralisée (MDM/SCCM) limite le déploiement de correctifs et de politiques de sécurité à distance. À évaluer selon le contexte du parc."
            anssi_ref      = "ANSSI-BP-028 R52"
        }
        Write-Verbose "[Workstation] WS-02 terminé : $valueText."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "WS-02"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = "Détection automatique impossible : $($_.ToString())"
            recommendation = "Vérifier manuellement l'inscription MDM (dsregcmd /status) et la présence d'un agent SCCM."
            anssi_ref      = "ANSSI-BP-028 R52"
        }
    }

    # --- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module    = [PSCustomObject]@{ name = "Workstation"; version = "1.0" }
        execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error = $null }
        results   = $results
    }

    Write-Verbose "[Workstation] Module Workstation terminé. $($results.Count) vérification(s) effectuée(s)."
    return $moduleResult
}