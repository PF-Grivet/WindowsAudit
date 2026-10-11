function Invoke-JsonRenderer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditReport,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [String]$ReportName
    )

    Write-Verbose "[JsonRenderer] Démarrage de la génération ddu rapport JSON."

    # --- Construction du chemin de sortie
    $fileName = "ReportName.json"
    $outputFile = Join-Path $OutputPath $fileName

    # --- Serialisation JSON indentité  (Depth 10 pour couvrir la structure imbriqué) ---
    try {
        $json = $AuditReport | ConvertTo-Json -Depth 10

        Set-content -Path $outputFile -Value $json -Encoding UTF8 -ErrorAction Stop

        Write-Verbose "[JsonRenderer] Rapport JSON ecrit : $outputFile"
    }
    catch {
        throw "[JsonRenderer] Impossible d'écrire le fichier JSON : $_"
    }

    return $outputFile
}
