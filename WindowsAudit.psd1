@{
    # Identité du module
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'WindowsAudit'
    CompanyName       = ''
    Copyright         = '2026'
    Description       = 'Outil d''audit de sécurité Windows aligné ANSSI BP-028. Diagnostic de la posture sécurité d''un poste Windows en PME.'

    # Version PowerShell minimale requise
    PowerShellVersion = '5.1'

    # Fichier racine du module
    RootModule        = 'WindowsAudit.psm1'

    # Fonctions exportées (accessibles après Import-Module)
    FunctionsToExport = @('Start-WindowsAudit')

    # Métadonnées
    PrivateData = @{
        PSData = @{
            Tags       = @('Security', 'Audit', 'ANSSI', 'Windows', 'PME')
            ProjectUri = ''
        }
    }
}
