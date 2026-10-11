function Invoke-HtmlRenderer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditReport,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ReportName
    )

    Write-Verbose "[HtmlRenderer] Démarrage de la génération du rapport HTML."

    # ---------------------------------------------------------------------------
    # FONCTIONS INTERNES
    # ---------------------------------------------------------------------------

    function Get-StatusBadge {
        param([string]$Status)
        switch ($Status) {
            "pass"   { return '<span class="badge pass">PASS</span>' }
            "fail"   { return '<span class="badge fail">FAIL</span>' }
            "manual" { return '<span class="badge manual">MANUEL</span>' }
            "error"  { return '<span class="badge error">ERREUR</span>' }
            default  { return '<span class="badge">?</span>' }
        }
    }

    function Get-SeverityBadge {
        param([string]$Severity)
        switch ($Severity) {
            "Critique" { return '<span class="sev critique">Critique</span>' }
            "Élevé"    { return '<span class="sev eleve">Élevé</span>' }
            "Moyen"    { return '<span class="sev moyen">Moyen</span>' }
            default    { return '<span class="sev">?</span>' }
        }
    }

    function Get-CheckScore {
        param([array]$Results)
        $pass  = ($Results | Where-Object { $_.status -eq "pass"  } | Measure-Object).Count
        $fail  = ($Results | Where-Object { $_.status -eq "fail"  } | Measure-Object).Count
        $errCount = ($Results | Where-Object { $_.status -eq "error" } | Measure-Object).Count
        $manual= ($Results | Where-Object { $_.status -eq "manual"} | Measure-Object).Count
        $total = $pass + $fail + $errCount
        $pct   = if ($total -gt 0) { [math]::Round($pass / $total * 100) } else { 0 }
        return [PSCustomObject]@{
            Pass   = $pass
            Fail   = $fail
            Error  = $errCount
            Manual = $manual
            Total  = $total
            Pct    = $pct
        }
    }

    function Get-ScoreColor {
        param([int]$Pct)
        if ($Pct -ge 80) { return "#2e7d32" }   # vert
        if ($Pct -ge 50) { return "#f57c00" }   # orange
        return "#c62828"                          # rouge
    }

    # ---------------------------------------------------------------------------
    # COLLECTE DES DONNÉES
    # ---------------------------------------------------------------------------

    $ctx        = $AuditReport.context
    $allResults = $AuditReport.modules | ForEach-Object { $_.results } | Where-Object { $_ }

    # Score global
    $globalScore = Get-CheckScore -Results $allResults

    # Score par niveau
    $scoreN1 = Get-CheckScore -Results ($allResults | Where-Object { $_.level -eq "N1" })
    $scoreN2 = Get-CheckScore -Results ($allResults | Where-Object { $_.level -eq "N2" })
    $scoreN3 = Get-CheckScore -Results ($allResults | Where-Object { $_.level -eq "N3" })

    # Top 3 priorités : checks fail/error, triés par sévérité
    $sevOrder = @{ "Critique" = 0; "Élevé" = 1; "Moyen" = 2 }
    $top3 = $allResults |
        Where-Object { $_.status -eq "fail" -or $_.status -eq "error" } |
        Sort-Object { if ($_.severity -and $sevOrder.ContainsKey($_.severity)) { $sevOrder[$_.severity] } else { 99 } } |
        Select-Object -First 3

    # Comptage global par statut
    $totalPass   = $globalScore.Pass
    $totalFail   = $globalScore.Fail
    $totalError  = $globalScore.Error
    $totalManual = $globalScore.Manual

    # ---------------------------------------------------------------------------
    # GÉNÉRATION HTML
    # ---------------------------------------------------------------------------

    $timestamp = $ctx.AuditTimestamp
    $hostname  = $ctx.Hostname
    $os        = $ctx.OsVersion
    $domain    = if ($ctx.IsDomainJoined) { "Domaine" } else { "Workgroup" }
    $admin     = if ($ctx.IsAdmin) { "Oui" } else { "Non" }

    $globalColor = Get-ScoreColor -Pct $globalScore.Pct
    $colorN1     = Get-ScoreColor -Pct $scoreN1.Pct
    $colorN2     = Get-ScoreColor -Pct $scoreN2.Pct
    $colorN3     = Get-ScoreColor -Pct $scoreN3.Pct

    # --- TOP 3 HTML ---
    $top3Html = ""
    if ($top3.Count -eq 0) {
        $top3Html = '<p class="no-issues">Aucun écart critique détecté.</p>'
    } else {
        foreach ($item in $top3) {
            $badge = Get-StatusBadge -Status $item.status
            $sev   = Get-SeverityBadge -Severity $item.severity
            $top3Html += @"
            <div class="priority-card">
                <div class="priority-header">
                    <span class="check-id">$($item.id)</span>
                    $sev
                    $badge
                </div>
                <div class="priority-value">$([System.Web.HttpUtility]::HtmlEncode($item.value))</div>
                <div class="priority-reco"><strong>Recommandation :</strong> $([System.Web.HttpUtility]::HtmlEncode($item.recommendation))</div>
                <div class="priority-anssi">Réf. ANSSI : $($item.anssi_ref)</div>
            </div>
"@
        }
    }

    # --- TABLEAU PAR MODULE ---
    $modulesHtml = ""
    foreach ($mod in $AuditReport.modules) {
        $modResults = $mod.results
        if (-not $modResults) { continue }
        $modScore = Get-CheckScore -Results $modResults
        $modColor = Get-ScoreColor -Pct $modScore.Pct
        $modName  = $mod.module.name
        $execMs     = $mod.execution.duration_ms

        $modulesHtml += @"
        <div class="module-block">
            <div class="module-header">
                <span class="module-name">$modName</span>
                <span class="module-score" style="color:$modColor">$($modScore.Pct)%</span>
                <span class="module-counts">
                    ✔ $($modScore.Pass) &nbsp; ✖ $($modScore.Fail) &nbsp; ⊘ $($modScore.Manual) &nbsp; ⚠ $($modScore.Error)
                </span>
                <span class="module-duration">${execMs} ms</span>
            </div>
            <table class="results-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Niveau</th>
                        <th>Sévérité</th>
                        <th>Statut</th>
                        <th>Valeur constatée</th>
                        <th>Recommandation</th>
                        <th>Réf. ANSSI</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($r in $modResults) {
            $statusBadge = Get-StatusBadge -Status $r.status
            $sevBadge    = Get-SeverityBadge -Severity $r.severity
            $valueEnc    = [System.Web.HttpUtility]::HtmlEncode($r.value)
            $recoEnc     = [System.Web.HttpUtility]::HtmlEncode($r.recommendation)
            $modulesHtml += @"
                    <tr>
                        <td class="check-id">$($r.id)</td>
                        <td>$($r.level)</td>
                        <td>$sevBadge</td>
                        <td>$statusBadge</td>
                        <td class="value-cell">$valueEnc</td>
                        <td class="reco-cell">$recoEnc</td>
                        <td class="anssi-cell">$($r.anssi_ref)</td>
                    </tr>
"@
        }
        $modulesHtml += @"
                </tbody>
            </table>
        </div>
"@
    }

    # ---------------------------------------------------------------------------
    # TEMPLATE HTML COMPLET
    # ---------------------------------------------------------------------------

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WindowsAudit — $hostname — $timestamp</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #1a1a2e; font-size: 14px; }

        /* En-tête */
        .header { background: #1a1a2e; color: #fff; padding: 24px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 22px; font-weight: 600; letter-spacing: 1px; }
        .header .meta { font-size: 12px; color: #a0aec0; text-align: right; line-height: 1.8; }

        /* Conteneur principal */
        .container { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }

        /* Sections */
        .section-title { font-size: 16px; font-weight: 700; color: #1a1a2e; border-left: 4px solid #3b82f6; padding-left: 12px; margin-bottom: 20px; margin-top: 36px; text-transform: uppercase; letter-spacing: 0.5px; }

        /* Cartes de contexte */
        .context-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 8px; }
        .context-card { background: #fff; border-radius: 8px; padding: 16px 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
        .context-card .label { font-size: 11px; color: #718096; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
        .context-card .val { font-size: 15px; font-weight: 600; color: #1a1a2e; }

        /* Score global */
        .score-global { background: #fff; border-radius: 8px; padding: 28px 32px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); display: flex; align-items: center; gap: 40px; margin-bottom: 8px; }
        .score-pct { font-size: 56px; font-weight: 800; color: $globalColor; line-height: 1; }
        .score-label { font-size: 13px; color: #718096; margin-top: 4px; }
        .score-breakdown { display: flex; gap: 24px; }
        .score-item { text-align: center; }
        .score-item .count { font-size: 24px; font-weight: 700; }
        .score-item .name  { font-size: 11px; color: #718096; text-transform: uppercase; }
        .count-pass   { color: #2e7d32; }
        .count-fail   { color: #c62828; }
        .count-manual { color: #1565c0; }
        .count-error  { color: #e65100; }

        /* Score par niveau */
        .level-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .level-card { background: #fff; border-radius: 8px; padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); text-align: center; }
        .level-card .level-name { font-size: 13px; font-weight: 700; text-transform: uppercase; color: #718096; margin-bottom: 8px; }
        .level-card .level-pct  { font-size: 36px; font-weight: 800; }
        .level-card .level-detail { font-size: 11px; color: #a0aec0; margin-top: 6px; }

        /* Top 3 priorités */
        .priority-card { background: #fff; border-radius: 8px; padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 12px; border-left: 4px solid #c62828; }
        .priority-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
        .priority-value  { font-size: 13px; color: #2d3748; margin-bottom: 8px; line-height: 1.5; }
        .priority-reco   { font-size: 12px; color: #4a5568; margin-bottom: 4px; }
        .priority-anssi  { font-size: 11px; color: #a0aec0; }
        .no-issues { color: #2e7d32; font-weight: 600; padding: 16px 0; }

        /* Badges statut */
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
        .badge.pass   { background: #e8f5e9; color: #2e7d32; }
        .badge.fail   { background: #ffebee; color: #c62828; }
        .badge.manual { background: #e3f2fd; color: #1565c0; }
        .badge.error  { background: #fff3e0; color: #e65100; }

        /* Badges sévérité */
        .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .sev.critique { background: #ffebee; color: #c62828; }
        .sev.eleve    { background: #fff3e0; color: #e65100; }
        .sev.moyen    { background: #fffde7; color: #f57f17; }

        /* Check ID */
        .check-id { font-family: monospace; font-size: 12px; font-weight: 700; color: #3b82f6; }

        /* Modules */
        .module-block { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 24px; overflow: hidden; }
        .module-header { display: flex; align-items: center; gap: 16px; padding: 16px 24px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
        .module-name  { font-size: 15px; font-weight: 700; color: #1a1a2e; flex: 1; }
        .module-score { font-size: 20px; font-weight: 800; }
        .module-counts { font-size: 12px; color: #718096; }
        .module-duration { font-size: 11px; color: #a0aec0; margin-left: auto; }

        /* Tableau résultats */
        .results-table { width: 100%; border-collapse: collapse; }
        .results-table th { background: #f1f5f9; font-size: 11px; text-transform: uppercase; color: #718096; padding: 10px 16px; text-align: left; letter-spacing: 0.4px; border-bottom: 1px solid #e2e8f0; }
        .results-table td { padding: 12px 16px; border-bottom: 1px solid #f1f5f9; vertical-align: top; font-size: 13px; }
        .results-table tr:last-child td { border-bottom: none; }
        .results-table tr:hover td { background: #f8fafc; }
        .value-cell { max-width: 320px; line-height: 1.5; color: #2d3748; }
        .reco-cell  { max-width: 280px; line-height: 1.5; color: #4a5568; }
        .anssi-cell { font-size: 11px; color: #a0aec0; white-space: nowrap; }

        /* Pied de page */
        .footer { text-align: center; padding: 32px; color: #a0aec0; font-size: 11px; }
    </style>
</head>
<body>

<div class="header">
    <h1>🔒 WindowsAudit — Rapport de sécurité</h1>
    <div class="meta">
        Généré le : $timestamp<br>
        Hôte : $hostname<br>
        OS : $os
    </div>
</div>

<div class="container">

    <!-- CONTEXTE -->
    <div class="section-title">Contexte du poste</div>
    <div class="context-grid">
        <div class="context-card"><div class="label">Hôte</div><div class="val">$hostname</div></div>
        <div class="context-card"><div class="label">Système d'exploitation</div><div class="val">$os</div></div>
        <div class="context-card"><div class="label">Environnement</div><div class="val">$domain</div></div>
        <div class="context-card"><div class="label">Audit en admin</div><div class="val">$admin</div></div>
        <div class="context-card"><div class="label">Date d'audit</div><div class="val">$timestamp</div></div>
    </div>

    <!-- VUE EXECUTIVE -->
    <div class="section-title">Vue executive</div>
    <div class="score-global">
        <div>
            <div class="score-pct">$($globalScore.Pct)%</div>
            <div class="score-label">Score global de conformité</div>
        </div>
        <div class="score-breakdown">
            <div class="score-item"><div class="count count-pass">$totalPass</div><div class="name">Pass</div></div>
            <div class="score-item"><div class="count count-fail">$totalFail</div><div class="name">Fail</div></div>
            <div class="score-item"><div class="count count-manual">$totalManual</div><div class="name">Manuel</div></div>
            <div class="score-item"><div class="count count-error">$totalError</div><div class="name">Erreur</div></div>
        </div>
    </div>

    <!-- SCORE PAR NIVEAU -->
    <div class="level-grid" style="margin-bottom: 8px;">
        <div class="level-card">
            <div class="level-name">N1 — Fondamentaux</div>
            <div class="level-pct" style="color:$colorN1">$($scoreN1.Pct)%</div>
            <div class="level-detail">✔ $($scoreN1.Pass) / ✖ $($scoreN1.Fail) / ⊘ $($scoreN1.Manual)</div>
        </div>
        <div class="level-card">
            <div class="level-name">N2 — Intermédiaire</div>
            <div class="level-pct" style="color:$colorN2">$($scoreN2.Pct)%</div>
            <div class="level-detail">✔ $($scoreN2.Pass) / ✖ $($scoreN2.Fail) / ⊘ $($scoreN2.Manual)</div>
        </div>
        <div class="level-card">
            <div class="level-name">N3 — Avancé</div>
            <div class="level-pct" style="color:$colorN3">$($scoreN3.Pct)%</div>
            <div class="level-detail">✔ $($scoreN3.Pass) / ✖ $($scoreN3.Fail) / ⊘ $($scoreN3.Manual)</div>
        </div>
    </div>

    <!-- TOP 3 PRIORITÉS -->
    <div class="section-title">Top 3 priorités</div>
    $top3Html

    <!-- VUE DÉTAILLÉE PAR MODULE -->
    <div class="section-title">Détail par module</div>
    $modulesHtml

</div>

<div class="footer">
    WindowsAudit v1.0 — Aligné ANSSI BP-028 — Rapport généré automatiquement — Usage interne uniquement
</div>

</body>
</html>
"@

    # ---------------------------------------------------------------------------
    # ÉCRITURE DU FICHIER
    # ---------------------------------------------------------------------------

    $fileName   = "$ReportName.html"
    $outputFile = Join-Path $OutputPath $fileName

    try {
        Set-Content -Path $outputFile -Value $html -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "[HtmlRenderer] Rapport HTML écrit : $outputFile"
    }
    catch {
        throw "[HtmlRenderer] Impossible d'écrire le fichier HTML : $_"
    }

    return $outputFile
}

