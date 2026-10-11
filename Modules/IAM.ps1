function Invoke-IAM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[IAM] Demarage du module IAM."

    $results = @()

    # --- IAM-01 : Comptes Admin inutiles ----
    try {
        $adminAccounts = Get-CimInstance Win32_GroupUser | Where-Object {
            $_.GroupComponent -match 'Name="Administrator"'
        } | ForEach-Object {
            $_.ParComponent -replace '.*Name="([^"]+)".*', '$1'
        }

        $builtinAdmins = @("Administrateur", "Administrator")
        $extraAdmins =$adminAccounts | Where-Object{$_ -notin $builtinAdmins}
        $count = {$extraAdmins | Measure-Object}.Count

        $results += [PSCustomObject]@{
            id = "IAM-01"
            level = "N1"
            severity = "Critique"
            status = if ($count -le 1) {"pass"} else {"fail"}
            value = "$count compte(s) Admin supplémentaire(s) : $($extraAdmins -join ', ')"
            recommendation = "Limiter le nombre de comptes Administrateur locaux au strict nécessaire (1 max hors compte intégré)."
            anssi_ref = "ANSSI-BP-028 R13"
        }
        Write-Verbose "[IAM] IAM-01 terminé : $count compte(s) Admin supplémentaire(s)."
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-01"
            level = "N1"
            severity ="Critique"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement les comptes mmenbres du groupe Administrateurs."
            anssi_ref = "ANSSI-BP-028 R13"
        }
    }
    # --------- IAM-02 : Compte Administratif intégré actif ------------
    try {
        $builtinAdmins = Get-CimInstance Win32_UserAccount | Where-Object {
            $_.SID -match '-500$'
        }
        $isEnabled = $builtinAdmins.Disabled -eq $false

        $results += [PSCustomObject]@{
            id = "IAM-02"
            level = "N1"
            severity = "Critique"
            status = if (-not $isEnabled) {"pass"} else {"fail"}
            value = if ($isEnabled) {"Compte Administrateur intégré actif ($($ $builtinAdmins.Name))"} else {"Compte Administrateur intégré desactivé."}
            recommendation = "Desactiver le compte Administrateur intégré et utiliser un compte admin nominatif."
            anssi_ref = "ANSSI-BP-028 R14"
        }
        Write-Verbose "[IAM] IAM-02 terminé: actif=$isEnabled"
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-02"
            level = "N1"
            severity ="Critique"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement l'état du compte Administrateur intégré'."
            anssi_ref = "ANSSI-BP-028 R14"        
        }
    
    }

    #--- IAM-03 : Politique de mot de passe ---
    try {
        $passPolicy = net acount 2>&1
        $minLength = ($passPolicy | Select-String "Longueur minimale | Minimum password length") -replace '\D+', ''
        $maxAge = ($passPolicy | Select-String "Durée maximale | Maximum password age") -replace '\D+', ''
        
        $minLengthInt = [int]($minLength | Select-Object -First 1)
        $maxAgeInt = [int]($maxAge | Select-Object -First 1)

        $status = if ($minLengthInt -ge 12 -and $maxAgeInt -le 90) {"pass"} else {"fail"}

        $results += [PSCustomObject]@{
            id ="IAM-03"
            level = "N1"
            severity ="Elevé"
            status = $status
            value = "Longeur minimale : $minLengthInt | Durée maximale : $maxAgeInt jours"
            recommendation = "Configurer une longueur minimale de 12 caractères et une durée maximale de 90 jours."
            anssi_ref = "ANSSI-BP-028 R17"        
        }
        Write-Verbose "[IAM] IAM-05 terminé: minLength=$minLengthInt maxAge=$maxAgeInt"
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-03"
            level = "N1"
            severity ="Elevé"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuelellement la politique de mots de passe locale"
            anssi_ref = "ANSSI-BP-028 R17"                
        }
    }
    
    # ------ IAM-04 : Password manager detecté -----------------
    $knownManagers = @("1Password", "Bitwarden", "Dashlane", "KeePass", "LastPass", "NordPass", "Keeper")
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOWN6432Node\Microsoft\Window\CurrentVesrion\Uninstall\*"
        )
        $allInstalled = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName} |
                        Select-Object -ExpandProperty DisplayName

        $found  = $allInstalled | Where-Object {
            $name = $_
            $knownManagers | Where-Object { $name -match $_}
        }
        $isFound = ($found | Measure-Object).Count -gt 0

        $results += [PSCustomObject]@{
            id ="IAM-04"
            level = "N1"
            severity ="Moyen"
            status = "manual"
            value = if ($isFound) {"Détecté : $($found -join ',')"} else {"Aucun gestionnaire de mots de passe détecté automatiquement."}
            recommendation = "Vérifier manuelellement'usage d'un gestionnaire de mots de passe approuvé par l'organisation."
            anssi_ref = "ANSSI-BP-028 R18"                
        }
        Write-Verbose "[IAM] IAM-04 terminé: détecté=$isFound"
    }
    catch{
        $results += [PSCustomObject]@{
            id ="IAM-04"
            level = "N1"
            severity ="Moyen"
            status = "manual"
            value = "Détection automatique impossible"
            recommendation = "Vérifier manuelellement que l'usage d'un gestionnaire de mots de passe approuvé par l'organisation."
            anssi_ref = "ANSSI-BP-028 R18"                
        }
    }

    #--- IAM-05 : MFA configuré --------------
    $results += [PSCustomObject]@{
        id ="IAM-05"
        level = "N1"
        severity ="Elevé"
        status = "manual"
        value = "Détection automatique du MFA non applicable sur poste local isolé"
        recommendation = "Vérifier manuelellement que le MFA est activé sur les comptes sensibles (Windows Hello, FIDO2, TOTP)."
        anssi_ref = "ANSSI-BP-028 R19"                
    }
    Write-Verbose "[IAM] IAM-05 : manual"
    
    # --- IAM-06 : USB désactivé ------------
    try{
        $usbStor = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction Stop
        $isDisabled = $usbStor.Start -eq 4
    
        $results += [PSCustomObject]@{
            id ="IAM-06"
            level = "N1"
            severity ="Elevé"
            status = if ($isDisabled) {"pass"} else {"fail"}
            value = if ($isDisabled) {"Service UBSTOR désactivé (Start=4)."} else {"Service UBSTOR actif (Start=$($usbStor.Start))."}
            recommendation = "Désactiver le service UBSTOR (Start=4) pour bloquer les périphériques de stockage USB."
            anssi_ref = "ANSSI-BP-028 R20"
        }
        Write-Verbose "[IAM] IAM-06 terminé: desactivé=$isDisable"
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-06"
            level = "N1"
            severity ="Elevé"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuelellement l'état du service UBSTOR dans le registre."
            anssi_ref = "ANSSI-BP-028 R20"                        
        }
    }

    # ---- IAM-07 : Bluetooth désactivé ---------
    try {
        $btService = Get-Service -Name "bthserv" -ErrorAction Stop
        $isDisabled = $btService.StartType -eq "Disabled"

        $results += [PSCustomObject]@{
            id ="IAM-07"
            level = "N1"
            severity ="Moyen"
            status = if ($isDisabled) {"pass"} else {"fail"}
            value =if ($isDisabled) {"Service Bluetooth désactivé."} else {"Service Bluetooth actif (StartType=$($btService.StartType)). "}
            recommendation = "Désactiver le service Bluetooth si non nécessaire."
            anssi_ref = "ANSSI-BP-028 R21"                        
        }        
        Write-Verbose "[IAM] IAM-07 terminé : désactivé=$isDisabled."
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-07"
            level = "N1"
            severity ="Moyen"
            status = "error"
            value = $_.ToString()
            recommendation = "Vérifier manuellement l'état du service Bluetooth."
            anssi_ref = "ANSSI-BP-028 R21"                    
        }
    }

    # ---- IAM-08 : Vérouillage de session -------------
    try {
        $lockPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction Stop
        $timeout = $lockPolicy.InactivityTimeoutSecs
        $status= if ($timeout -gt 0 -and $timeout -le 600) {"pass"} else {"fail"}

        $results += [PSCustomObject]@{
            id ="IAM-08"
            level = "N1"
            severity ="Moyen"
            status = $status
            value = "Délai de vérouillage: $timeout secondes."
            recommendation = "Configurer un délai de vérouillage automatique de 10 minutes maximum (600 secondes)."
            anssi_ref = "ANSSI-BP-028 R22"                    
        }
        Write-Verbose "[IAM] IAM-08 terminé: timeout=$timeout s."
    }
    catch {
        $results += [PSCustomObject]@{
            id ="IAM-08"
            level = "N1"
            severity ="Elevé"
            status = "fail"
            value = "Clé InactivityTimeoutSecs absente -verouillage automatique non configuré."
            recommendation = "Configurer un délai de vérouillage automatique de 10 min maximun (600 secondes)."
            anssi_ref = "ANSSI-BP-028 R22"                    
        }
        Write-Verbose "[IAM] IAM-08 : clé absente, fail"
    }

        # ---- Construction du Module Result ----
        $moduleResults = [PSCustomObject]@{
            module = [PSCustomObject]@{ name="IAM"; version = "1.0" }
            execution = [PSCustomObject]@{ duration_ms =0; status = "success"; error = $null }
            results = $results
        }

       Write-Verbose "[IAM] Module IAM terminé. $($results.Count) vérification(s) effectuée(s)."
       return $moduleResults
       
}

