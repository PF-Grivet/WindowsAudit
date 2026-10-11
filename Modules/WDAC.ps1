function Invoke-WDAC {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[WDAC] Démarrage du module WDAC"

    $results = @()

    #--- Vérification des droits admin ---
    if (-not $AuditContext.IsAdmin) {
        foreach ($checkId in @("WDAC-01", "WDAC-02", "WDAC-03")){
            $results += [PSCustomObject]@{
                id = $checkId
                level = "N3"
                severity = if ($checkId -eq "WDAC-01") {"Elevé"} elseif ($checkId -eq "WDAC-02") {"Critique"} else {"Elevé"}
                status = "manual"
                value = "Lecture de la configuration WDAC nécessite des droits administrateur. Relancer l'audit en droit admin pour ce check."
                recommendation = switch ($checkId) {
                    "WDAC-01" {"Activer WDAC pour contrôler les applications autorisées à s'exécuter sur le poste."  }
                    "WDAC-02" {"Configurer WDAC en mode Enforce pour bloquer les applications nons autorisées"}
                    "WDAC-03" {"Signer la politique WDAC pour la protéger contre toute falsification"}
                }
                anssi_ref = "ANSSI-BP-028 R81"
            }
        }
        Write-Verbose "[WDAC] Tous les checks : manual, admin requis."

        $moduleResult = [PSCustomObject]@{
            module = [PSCustomObject]@{ name="WDAC"; version="1.0"}
            execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error= $null}
            results = $results
        }
        return $moduleResult
    }

    # --- Lecture configuration WDAC cua registre
    $ciConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $ciPoliciesPath = "C:\Windows\System32\CodeIntegrity\CIPolicies\Active"
    $ciLegacyPath = "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

    # --- WDAC-01 : WDAC activé --------------
    try {
        $ciConfig = Get-ItemProperty -Path $ciConfigPath -ErrorAction Stop

        # VerboseHash > 0 ou présence de politiques actives indique WDAC actif
        $policiesPresent = (Test-Path $ciPoliciesPath) -and ((Get-ChildItem $ciPoliciesPath -Filter "*.cip" -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
        $legacyPresent = Test-Path $ciLegacyPath
        $wdacEnabled = $policiesPresent -or $legacyPresent

        $valueText = if ($wdacEnabled){
            if ($policiesPresent){ "WDAC actif - politique(s) détectée(s) dans CiPolicies\Active"}
            else { "WDAC actif - politique legacy SIPolicy.p7b détectée."}
        } else { 
            "Aucune politique dégtectée."    
        }

        $results += [PSCustomObject]@{
                id = "WDAC-01"
                level = "N3"
                severity = "Elevé"
                status = if ($wdacEnabled) {"pass"} else {"fail"}
                value = $valueText
                recommendation = "Activer WDAC pour contrôler les applications autorissées à s'exécuter sur le poste."
                anssi_ref = "ANSSI-BP-028 R81"
        }
        Write-Verbose "[WDAC] WDAC-01 terminé : activité=$wdacEnabled."

        # --- WDAC-02 : Mode Audit vs Enforce
        try {
            if (-not $wdacEnabled){
                $results += [PSCustomObject]@{
                    id = "WDAC-02"
                    level = "N3"
                    severity = "Critique"
                    status = "fail"
                    value = "WDAC non activé - mode Audit/Enforce non applicable"
                    recommendation = "Activer WDAC avant de configurer le mode Enforce."
                    anssi_ref = "ANSSI-BP-028 R82"
                }
            }
            else {
                #Lire l'option d'enforcement via le registre CI
                $enforcementMode = $ciConfig.VerifiedAndReputablePolicyState
                # 0 = off, 1 = Audit, 2 = Enforce - ou via presence de politique enforce
                $isEnforce = $null -ne $enforcementMode -and $enforcementMode -eq 2

                # Méthode alternative : inspecter les option de politique dans le fichier 
                $policyFiles = if ($policiesPresent){
                    Get-ChildItem $ciPoliciesPath -Filter "*.cip" -ErrorAction SilentlyContinue
                } else {$null}

                $modeText = if ($isEnforce) {"Enforce"} else {"Audit (ou indeterminé)"}

                $results += [PSCustomObject]@{
                    id = "WDAC-02"
                    level = "N3"
                    severity = "Critique"
                    status = if ($isEnforce) {"pass"} else {"fail"}
                    value = "WDAC non detecté : $modeText. Nombre de politique actives : $(if ($policyFiles) {($policyFiles | Measure-Object).count} else {'N/A(legacy)'})."
                    recommendation = "Configurer WDAC en mode Enforce après une phase de test en Audit pour bloquer les applications non autorisées."
                    anssi_ref = "ANSSI-BP-028 R82"
                }
                Write-Verbose "[WDAC] WDAC-02 terminé : mide=$modeText."
            }
        }
        catch {
            $results += [PSCustomObject]@{
                    id = "WDAC-02"
                    level = "N3"
                    severity = "Critique"
                    status = "error"
                    value = $_.ToString()
                    recommendation = "Vérifier manuellement le mode WDAC (Audit/Enforce)."
                    anssi_ref = "ANSSI-BP-028 R82"
            }
        }

        # --- WDAC-03 : Politique signée -----
        try {
            if (-not $wdacEnabled) {
                $results += [PSCustomObject]@{
                    id = "WDAC-02"
                    level = "N3"
                    severity = "Critique"
                    status = "fail"
                    value = "WDAC non activé - signature de politique non applicable"
                    recommendation = "Activer WDAC et signer la politique pour la protéger contre toute falsification."
                    anssi_ref = "ANSSI-BP-028 R83"
                }
            }
            else {
                # Une politique .cip peuvent être signé ou non - on marque manuel car
                # La détection fiable nécessite un parsing binaire hors scope v1
                $isSigned = $legacyPresent # SIPolicy.p7b = toujours signé

                if ($policiesPresent -and -not $legacyPresent) {
                    # Les fichiers .cip peuvent être signés ou non - on marque manual car
                    # la détection fiable nécessite un parsing binaire hors scope V1
                    $results += [PSCustomObject]@{
                        id = "WDAC-03"
                        level = "N3"
                        severity = "Elevé"
                        status = "manual"
                        value = "Politique(s) .cip détectée(s) - signature non verfiable automatiquement en v1. Vérifier via l'outil WDAC Wizard ou CiTool."
                        recommendation = "Signer la politique WDAC avec un certificat de code pour la protéger contre toute falsification ou suppression non autoriséé."
                        anssi_ref = "ANSSI-BP-028 R83"
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        id = "WDAC-03"
                        level = "N3"
                        severity = "Elevé"
                        status = if ($isSigned) {"pass"} else {"fail"}
                        value = if ($isSigned) {"Politique SIPolicy.p7b détectée - format signé (PKCS#7)"} else {"Politique non signée détectée"}
                        recommendation = "Signer la politique WDAC avec un certificat de code pour la protéger contre toute falsification ou suppression non autoriséé."
                        anssi_ref = "ANSSI-BP-028 R83"                    
                    }
                }
                Write-Verbose "[WDAC] WDAC-03 terminé"
            }
        }
        catch {
            $results += [PSCustomObject]@{
                id = "WDAC-03"
                level = "N3"
                severity = "Elevé"
                status = "error"
                value = $_.ToString()
                recommendation = "Vérifier manuellement si la politique WDAC est signée."
                anssi_ref = "ANSSI-BP-028 R83"                    
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            id = "WDAC-01"
            level = "N3"
            severity = "Elevé"
            status = "Error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement la Configuration WDAC via le registre HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config."
            anssi_ref = "ANSSI-BP-028 R81"                    
        }
    }

    #--- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module = [PSCustomObject]@{ name = "WDAC"; version = "1.0"}
        execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error = $null}
        results =$results
    }
    Write-Verbose "[WDAC] Module WDAC terminé. $($results.Count) vérifications(s) effectuée(s)."
    return $moduleResult
}


