function Invoke-Patches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[Patches] Démarrage du module Patches."

    $results = @()

    # --- PATCH-01 : Windows Update activé et configuré ---
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        $isRunning  = $wuService.Status -eq "Running"
        $isEnabled  = $wuService.StartType -ne "Disabled"

        $auSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
        $auEnabled  = $auSettings.NotificationLevel -ge 3  # 3=Auto download, 4=Auto install

        $status = if ($isEnabled -and $isRunning -and $auEnabled) { "pass" } else { "fail" }
        $auLevel = $auSettings.NotificationLevel
        $value  = "Service wuauserv : $(if ($isEnabled) {'actif'} else {'désactivé'}),  " +
                  "$(if ($isRunning) {'en cours'} else {'arrêté'}) | " +
                  "Mises à jour automatiques : $(if ($auEnabled) {"configurées (niveau $auLevel)"} else {'non configurées'})"

        $results += [PSCustomObject]@{
            id             = "PATCH-01"
            level          = "N1"
            severity       = "Critique"
            status         = $status
            value          = $value
            recommendation = "Activer le service Windows Update et configurer les mises à jour automatiques."
            anssi_ref      = "ANSSI-BP-028 R61"
        }
        Write-Verbose "[Patches] PATCH-01 terminé : service=$($wuService.Status) auEnabled=$auEnabled."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "PATCH-01"
            level          = "N1"
            severity       = "Critique"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'état du service Windows Update."
            anssi_ref      = "ANSSI-BP-028 R61"
        }
    }

    # --- PATCH-02 : Dernière mise à jour installée ---
    try {
        $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $daysSince  = if ($lastUpdate.InstalledOn) {
            [math]::Round(((Get-Date) - $lastUpdate.InstalledOn).TotalDays)
        } else { 999 }

        $status = if ($daysSince -le 30) { "pass" } elseif ($daysSince -le 60) { "fail" } else { "fail" }

        $results += [PSCustomObject]@{
            id             = "PATCH-02"
            level          = "N1"
            severity       = "Élevé"
            status         = $status
            value          = "Dernier correctif : $($lastUpdate.HotFixID) installé le $($lastUpdate.InstalledOn.ToString('yyyy-MM-dd')) (il y a $daysSince jours)."
            recommendation = "S'assurer que les correctifs de sécurité sont appliqués dans un délai de 30 jours."
            anssi_ref      = "ANSSI-BP-028 R61"
        }
        Write-Verbose "[Patches] PATCH-02 terminé : dernière MAJ il y a $daysSince jours."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "PATCH-02"
            level          = "N1"
            severity       = "Élevé"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement la date du dernier correctif installé."
            anssi_ref      = "ANSSI-BP-028 R61"
        }
    }

    # --- PATCH-03 : Logiciels à risque détectés ---
    try {
        $refPath = Join-Path $RootPath "References\RiskySoftware.json"

        if (-not (Test-Path $refPath)) {
            throw "Fichier de référence introuvable : $refPath"
        }

        $refData      = Get-Content $refPath -Raw | ConvertFrom-Json
        $riskySoftware = $refData.risky_software

        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $installedNames = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
                          Where-Object { $_.DisplayName } |
                          Select-Object -ExpandProperty DisplayName

        $found = foreach ($software in $riskySoftware) {
            $match = $installedNames | Where-Object { $_ -match $software.name }
            if ($match) {
                [PSCustomObject]@{
                    name     = $match
                    reason   = $software.reason
                    severity = $software.severity
                }
            }
        }

        $foundCount = ($found | Measure-Object).Count
        $status     = if ($foundCount -eq 0) { "pass" } else { "fail" }
        $valueText  = if ($foundCount -eq 0) {
            "Aucun logiciel à risque détecté (référentiel : $($refData.last_updated))."
        } else {
            "$foundCount logiciel(s) à risque : $($found.name -join ', ')."
        }

        $results += [PSCustomObject]@{
            id             = "PATCH-03"
            level          = "N1"
            severity       = "Élevé"
            status         = $status
            value          = $valueText
            recommendation = "Désinstaller ou mettre à jour les logiciels identifiés comme présentant un risque de sécurité."
            anssi_ref      = "ANSSI-BP-028 R62"
        }
        Write-Verbose "[Patches] PATCH-03 terminé : $foundCount logiciel(s) à risque détecté(s)."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "PATCH-03"
            level          = "N1"
            severity       = "Élevé"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier la présence du fichier References\RiskySoftware.json."
            anssi_ref      = "ANSSI-BP-028 R62"
        }
    }

    # --- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module    = [PSCustomObject]@{ name = "Patches"; version = "1.0" }
        execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error = $null }
        results   = $results
    }

    Write-Verbose "[Patches] Module Patches terminé. $($results.Count) vérification(s) effectuée(s)."
    return $moduleResult
}
