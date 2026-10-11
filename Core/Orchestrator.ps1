function Invoke-Orchestrator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$AuditParameters,

        [Parameter(Mandatory)]
        [PSCustomObject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$RootPath
    )
    
    Write-verbose "[Orchestrator] Démarage de l'orchestration."

    #---- Table de correspondance Level -> Module autorisés ----
    $levelMap = @{
        "N1"=@("IAM", "Patches")
        "N1N2"=@("IAM", "Patches", "Network", "Logs", "Workstation")
        "All"=@("IAM", "Patches", "Network", "Logs", "Workstation", "ASR", "WDAC")     
    }

    #---- Determiner les modules à exécuter ---
    if ($AuditParameters.Module) {
        $moduleToRun = @($AuditParameters.Module)
        Write-Verbose "[Orchestrator] Mode module unique : $($AuditParameters.Module)."
    }
    else {
        $moduleToRun = $levelMap[$AuditParameters.Level]
        Write-Verbose "[Orchestrator] Mode niveau : $($AuditParameters.Level) -> $($moduleToRun -join ', ')."
    }

    # --- Charger les modules disoponibles et filtrer dynamiquement ----
    $moduleResults = @()

    foreach ($moduleName in $moduleToRun) {
        $modulePath = Join-Path $RootPath "\Modules\$moduleName.ps1"
    
        # --- Vérifier que le fichier module existe déja
        if (-not (Test-Path $modulePath)) {
            Write-Warning "[WinddowsAudit] Module '$moduleName' introuvable: $modulePath"
            $moduleResults += [PSCustomObject]@{
                module = [PSCustomObject]@{ name =$moduleName; version ="N/A"}
                execurtion = [PSCustomObject]@{ duration_ms=0; status = "not_found"; error = "Fichier module introuvable."}
                results = @()
            }
        continue
        }

        # ----- Charger le module --------------
        try {
            .$modulePath
            Write-Verbose "[Orchestrator] Module '$moduleName' chargé."
        }
        Catch {
            Write-Warning "[WindowsAudit] Impossible de charger le module '$moduleName' : $_"
            $moduleResults += [PSCustomObject]@{
                module = [PSCustomObject]@{ name = $moduleName; version ="N/A"}
                execution = [PSCustomObject]@{ duration_ms = 0;status ="load_error"; error = $_.ToString()}
                results = @()
            }
            continue
        }

        # --- Exécuter le module ----
        $startTime = Get-Date
        try {
            Write-Verbose "[Orchestrator] Execution du module '$moduleName'."
            $invokeName = "Invoke-$moduleName"
            $result = & $invokeName -AuditContext $AuditContext -RootPath $RootPath
            $duration = [int]((Get-Date) -$startTime).TotalMilliseconds

            Write-Verbose "[Orchestrator] Module '$moduleName' termine en $duration ms."
            $result.execution.duration_ms = $duration
            $result.execution.status = "success"
            $moduleResults += $result
        }
        catch {
            $duration = [int]((Get-Date) - $startTime).TotalMilliseconds
            Write-Warning "[WindowsAudit] Erreur lors de l'execution du module '$moduleName' : $_"
            $moduleResults += [PSCustomObject]@{
                module = [PSCustomObject]@{ name = $moduleName; version = "N/A"}
                execution = [PSCustomObject]@{ duration_ms = $duration; status = "error"; error = $_.ToString()}
                results = @()
            }
        }

    }

    # --- Construction de l'AuditReport ----
    $auditReport = [PSCustomObject]@{
        context = $AuditContext
        parameters = $AuditParameters
        modules = $moduleResults
    }

    Write-Verbose "[Orchestrator] AuditReport construit. $($moduleResults.Count) module(s) traité(s)"
    return $auditReport
}





