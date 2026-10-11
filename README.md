# WindowsAudit

Outil d'audit de sécurité PowerShell pour postes Windows, aligné sur le référentiel **ANSSI BP-028**.  
Génère un rapport HTML avec score, statut par contrôle et recommandations priorisées.

---

## Prérequis

- Windows 10/11
- PowerShell 7 (`pwsh`)
- **Droits administrateur** (obligatoire pour tous les contrôles)

---

## Installation

```powershell
# 1. Cloner le dépôt
git clone https://github.com/PF-Grivet/WindowsAudit.git

# 2. Aller dans le dossier
cd WindowsAudit

# 3. Importer le module (depuis un PowerShell en admin)
Import-Module .\WindowsAudit.psd1
```

---

## Utilisation

```powershell
# Audit niveau 1 uniquement
.\WindowsAudit.ps1 -Level N1

# Audit niveaux 1 et 2
.\WindowsAudit.ps1 -Level N1N2

# Audit complet
.\WindowsAudit.ps1 -Level All
```

Le rapport HTML est généré dans le dossier `Output\`.

---

## Modules

| Module | Contrôles |
|--------|-----------|
| **Network** | Pare-feu, partages réseau, protocoles |
| **Logs** | Journalisation Windows, audit events |
| **Workstation** | Mises à jour, BitLocker, écran de veille |
| **IAM** | Comptes locaux, mots de passe, groupes admin |
| **WDAC** | Windows Defender Application Control |
| **ASR** | Attack Surface Reduction rules |

---

## Structure du projet

```
WindowsAudit/
├── WindowsAudit.ps1
├── WindowsAudit.psm1
├── WindowsAudit.psd1
├── Core/
│   ├── AuditContext.ps1
│   └── Orchestrator.ps1
├── Modules/
│   ├── Network.ps1
│   ├── Logs.ps1
│   ├── Workstation.ps1
│   ├── IAM.ps1
│   ├── WDAC.ps1
│   └── ASR.ps1
├── Renderers/
│   └── HtmlRenderer.ps1
├── References/
│   └── ASR_Baseline.json
└── Output/
```

---

## Référence ANSSI

Aligné sur le guide **ANSSI BP-028** :  
https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-aux-systemes-windows

---

## Licence

Usage interne uniquement — non destiné à la distribution publique.
