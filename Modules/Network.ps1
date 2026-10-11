function Invoke-Network {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    Write-Verbose "[Network] Démarrage du module Network."

    $results = @()

    # --- NET-01 : Profil réseau ---
    try {
        $profiles = Get-NetConnectionProfile

        if (($profiles | Measure-Object).Count -eq 0) {
            $valueText = "Aucun profil réseau actif détecté."
        }
        else {
            $profileList = $profiles | ForEach-Object { "$($_.InterfaceAlias) : $($_.NetworkCategory)" }
            $valueText = "Profil(s) détecté(s) : $($profileList -join ' | ')"
        }

        $results += [PSCustomObject]@{
            id             = "NET-01"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = $valueText
            recommendation = "Vérifier que le profil réseau (Public/Privé/Domaine) correspond au contexte d'usage du poste."
            anssi_ref      = "ANSSI-BP-028 R31"
        }
        Write-Verbose "[Network] NET-01 terminé : $valueText."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-01"
            level          = "N2"
            severity       = "Moyen"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement le profil réseau via Get-NetConnectionProfile."
            anssi_ref      = "ANSSI-BP-028 R31"
        }
    }

    # --- NET-02 : Interfaces actives (risque de bridging) ---
    try {
        # InterfaceType 6 = Ethernet 802.3, 71 = IEEE 802.11 (WiFi)
        $physicalAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq "Up" -and $_.InterfaceType -in @(6, 71)
        }

        $count = ($physicalAdapters | Measure-Object).Count
        $names = ($physicalAdapters | ForEach-Object { "$($_.Name) ($($_.InterfaceDescription))" }) -join ', '

        $status = if ($count -le 1) { "pass" } else { "fail" }
        $valueText = "$count interface(s) physique(s) active(s) simultanément : $names"

        $results += [PSCustomObject]@{
            id             = "NET-02"
            level          = "N2"
            severity       = "Élevé"
            status         = $status
            value          = $valueText
            recommendation = "Éviter d'avoir plusieurs interfaces physiques actives simultanément (risque de pont réseau / bridging)."
            anssi_ref      = "ANSSI-BP-028 R32"
        }
        Write-Verbose "[Network] NET-02 terminé : $count interface(s) physique(s) active(s)."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-02"
            level          = "N2"
            severity       = "Élevé"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement les interfaces réseau actives via Get-NetAdapter."
            anssi_ref      = "ANSSI-BP-028 R32"
        }
    }

    # --- NET-03 : Pare-feu activé sur tous les profils ---
    try {
        $fwProfiles = Get-NetFirewallProfile

        $detail = $fwProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }
        $allEnabled = -not ($fwProfiles | Where-Object { $_.Enabled -eq $false })

        $results += [PSCustomObject]@{
            id             = "NET-03"
            level          = "N2"
            severity       = "Critique"
            status         = if ($allEnabled) { "pass" } else { "fail" }
            value          = "État pare-feu par profil : $($detail -join ' | ')"
            recommendation = "Activer le pare-feu Windows sur les 3 profils (Domaine, Privé, Public)."
            anssi_ref      = "ANSSI-BP-028 R33"
        }
        Write-Verbose "[Network] NET-03 terminé : $($detail -join ', ')."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-03"
            level          = "N2"
            severity       = "Critique"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'état du pare-feu via Get-NetFirewallProfile."
            anssi_ref      = "ANSSI-BP-028 R33"
        }
    }

    # --- NET-04 : Règles entrantes deny all par défaut ---
    try {
        $fwProfiles = Get-NetFirewallProfile

        $detail = $fwProfiles | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction)" }
        $allBlock = -not ($fwProfiles | Where-Object { $_.DefaultInboundAction -ne "Block" })

        $results += [PSCustomObject]@{
            id             = "NET-04"
            level          = "N2"
            severity       = "Critique"
            status         = if ($allBlock) { "pass" } else { "fail" }
            value          = "Action entrante par défaut par profil : $($detail -join ' | ')"
            recommendation = "Configurer le blocage par défaut du trafic entrant (deny all) sur les 3 profils."
            anssi_ref      = "ANSSI-BP-028 R34"
        }
        Write-Verbose "[Network] NET-04 terminé : $($detail -join ', ')."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-04"
            level          = "N2"
            severity       = "Critique"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement l'action entrante par défaut via Get-NetFirewallProfile."
            anssi_ref      = "ANSSI-BP-028 R34"
        }
    }

    # --- NET-05 : Client VPN présent ---
    $knownVpnClients = @("AnyConnect", "FortiClient", "GlobalProtect", "OpenVPN", "Pulse Secure", "SonicWall", "WireGuard")
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $installedNames = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
                          Where-Object { $_.DisplayName } |
                          Select-Object -ExpandProperty DisplayName

        $found = $installedNames | Where-Object {
            $name = $_
            $knownVpnClients | Where-Object { $name -match $_ }
        }
        $isFound = ($found | Measure-Object).Count -gt 0

        $results += [PSCustomObject]@{
            id             = "NET-05"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = if ($isFound) { "Client(s) VPN détecté(s) : $($found -join ', ')" } else { "Aucun client VPN connu détecté automatiquement." }
            recommendation = "Vérifier manuellement la présence et la configuration d'un client VPN d'entreprise pour les accès distants."
            anssi_ref      = "ANSSI-BP-028 R35"
        }
        Write-Verbose "[Network] NET-05 terminé : détecté=$isFound."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-05"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = "Détection automatique impossible."
            recommendation = "Vérifier manuellement la présence et la configuration d'un client VPN d'entreprise pour les accès distants."
            anssi_ref      = "ANSSI-BP-028 R35"
        }
    }

    # --- NET-06 : Passerelle ---
    try {
        $gateways = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } |
                    ForEach-Object { "$($_.InterfaceAlias) : $($_.IPv4DefaultGateway.NextHop)" }

        $valueText = if (($gateways | Measure-Object).Count -gt 0) {
            "Passerelle(s) détectée(s) : $($gateways -join ' | ')"
        } else {
            "Aucune passerelle par défaut détectée."
        }

        $results += [PSCustomObject]@{
            id             = "NET-06"
            level          = "N2"
            severity       = "Moyen"
            status         = "manual"
            value          = $valueText
            recommendation = "Vérifier que la passerelle par défaut correspond à l'infrastructure réseau attendue."
            anssi_ref      = "ANSSI-BP-028 R36"
        }
        Write-Verbose "[Network] NET-06 terminé : $valueText."
    }
    catch {
        $results += [PSCustomObject]@{
            id             = "NET-06"
            level          = "N2"
            severity       = "Moyen"
            status         = "error"
            value          = $_.ToString()
            recommendation = "Vérifier manuellement la passerelle par défaut via Get-NetIPConfiguration."
            anssi_ref      = "ANSSI-BP-028 R36"
        }
    }

    # --- Construction du ModuleResult ---
    $moduleResult = [PSCustomObject]@{
        module    = [PSCustomObject]@{ name = "Network"; version = "1.0" }
        execution = [PSCustomObject]@{ duration_ms = 0; status = "success"; error = $null }
        results   = $results
    }

    Write-Verbose "[Network] Module Network terminé. $($results.Count) vérification(s) effectuée(s)."
    return $moduleResult
}
