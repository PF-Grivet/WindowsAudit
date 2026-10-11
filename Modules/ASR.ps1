function Invoke-ASR {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [String]$RootPath
    )

    Write-Verbose "[ASR Demarage du module ASR.]"

    $results =@()

    # --- ASR-01 : ASR activé (présence de règles configurées) ---
    if (-not $AuditContext.IsAdmin){
        $results +=[PSCustomObject]@{
            Id = "ASR-01"
            level = "N3"
            severrity = "Elevé"
            status = "manual"
            value = "Lecture de la configuration ASR nécessit des droits administrateur. Relancer l'audit en mode admin pour ce check"
            recommendation = "Activier et configurer les règles ASR via Microsoft Defender."
            anssi_ref = "ANSSI-BP-028 R71"
        }
        $results += [PSCustomObject]@{
            Id = "ASR-02"
            level = "N3"
            severrity = "Critique"
            status = "manual"
            value = "Lecture de la configuration ASR nécessit des droits administrateur. Relancer l'audit en mode admin pour ce check"
            recommendation = "Configurer les règles ASR critiques en mode Block."
            anssi_ref = "ANSSI-BP-028 R72"
        }
        Write-Verbose "[ASR] ASR-01 et ASR-02 : manual, droits admin requis."

        $moduleResult = [PSCustomObject]@{
            module = [PSCustomObject]@{ name="ASR"; version ="1.0"}
            execution = [PSCustomObject]@{ duration_ms =0 ; status = "sucess"; error = $null}
            results = $results
        }
        return $moduleResult
    }

    # ---- Leccture de la configuration ASR -------
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $asrIds = $mpPref.AttackSufaceReductionRules_Ids
        $asrActions = $mpPref.AttackSufaceReductionRules_Actions

        $asrEnabled = ($asrIds | Measure-Object).Count -gt 0

        # Construire un dictionnaire GUID -> action configurée
        $configureRules = @{}
        if ($asrEnabled) {
            for ($i = 0; $i -lt $asrIds.count; $i++){
                $configureRules[$asrIds[$i].ToLower()] = $asrActions[$i]
            }
        }

        #ASR-01 : ASR activé
        $results += [PSCustomObject]@{
            Id = "ASR-01"
            level = "N3"
            severrity = "Elevé"
            status = if ($asrEnabled) {"pass"} else {"fail"}
            value = if ($asrEnabled) {"$($asrIds.Count) règle(s) ASR configurée(s)"} else {"Aucune règle ASR configurée"}
            recommendation = "Activer et configurer les règles ASR via Microsoft Defender."
            anssi_ref = "ANSSI-BP-028 R71"
        }
        Write-Verbose "[ASR] ASR-01 terminé: activté=$asrEnabled ($($asrIds.Count) règles)"

        # --- ASR-02 : règles critiques en block vs audit
        $refPath = Join-Path $RootPath "References\ASR_Baseline.json"

        if (-not (Test-Path $refPath)){
            throw "Fichier de référence introuvable : $refPath"
        }

        $baseline = Get-Content $refPath -Raw | ConvertFrom-Json
        $criticalRules = $baseline.rules | Where-Object { $_.critical -eq $true}

        $auditOnly = @()
        $missing = @()
        $blocked = @()

        foreach ($rule in $criticalRules) {
            $guid = $rule.id.ToLower()
            if ($configureRules.ContainsKey($guid)){
                $action = $configureRules[$guid]
                if ($action -eq 2) {
                    $blocked += $rule.name                  
                } else {
                    $auditOnly += $rule.name
                }
            } else {
                $missing +=$rule.name
            }
        }

        $totalCritical = ($criticalRules | Measure-Object).Count
        $blockedCount = ($blocked | Measure-Object).Count
        $auditCount = ($auditOnly | Measure-Object).Count
        $missingCount = ($missing | Measure-Object).Count

        $status = if ($blockedCount -eq $totalCritical) {"pass"} else {"fail"}

        $valueText = "$blockedCount/$totalCritical règles critiques en Block"
        if ($auditCount -gt 0) {$valueText += " | $auditCount en Audit seulement"}
        if ($missingCount -gt 0) {$valueText += " | $missingCount en Audit seulement"}

        $results += [PSCustomObject]@{
            Id = "ASR-03"
            level = "N3"
            severrity = "Critique"
            status = $status
            value = $valueText
            recommendation = "Passer toutes les règles ASR critiques du référentiel en mode Block. Commencer par les tester en Audit avant déploiement."
            anssi_ref = "ANSSI-BP-028 R72"
        }
        Write-Verbose "[ASR] ASR-02 terminé : $blockCount/$totalCritical critiques en Block"
    }
    catch {
        $results += [PSCustomObject]@{
            Id = "ASR-01"
            level = "N3"
            severrity = "Elevé"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement la configuration ASR via Get-MpPreference."
            anssi_ref = "ANSSI-BP-028 R71"
        }
    }
    # --- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module = [PSCustomObject]@{ name = "ASR" ; version = "1.0"  }
        execution = [PSCustomObject]@{ duration_ms = 0 ; status = "success"; error = $null}
        results = $results
    }

    Write-Verbose "[ASR] Module ASR terminé. $($results.Count) vérifications(s) effecctués."
    return $moduleResult
}