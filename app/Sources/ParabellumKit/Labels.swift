import Foundation

// French user-facing labels for every enum shown in the UI.

extension Verdict {
    public var label: String {
        switch self {
        case .clean: return "Sain"
        case .suspicious: return "Suspect"
        case .malicious: return "Malveillant"
        case .unknown: return "Inconnu"
        }
    }
}

extension Severity {
    public var label: String {
        switch self {
        case .info: return "Info"
        case .low: return "Faible"
        case .medium: return "Moyenne"
        case .high: return "Élevée"
        case .critical: return "Critique"
        case .unknown: return "Inconnue"
        }
    }
}

extension DetectionEngine {
    public var label: String {
        switch self {
        case .hashDb: return "Base de hash"
        case .clamav: return "ClamAV"
        case .yara: return "YARA"
        case .ml: return "Modèle ML"
        case .heuristic: return "Heuristique"
        case .virusTotal: return "VirusTotal"
        case .unknown: return "Moteur inconnu"
        }
    }
}

extension FileKind {
    public var label: String {
        switch self {
        case .macho: return "Exécutable Mach-O"
        case .fatMacho: return "Mach-O universel"
        case .dmg: return "Image disque (DMG)"
        case .pkg: return "Paquet d'installation (PKG)"
        case .zip: return "Archive ZIP"
        case .script: return "Script"
        case .appBundle: return "Application"
        case .document: return "Document"
        case .archive: return "Archive"
        case .other: return "Autre"
        }
    }
}

extension ScanOrigin {
    public var label: String {
        switch self {
        case .manual: return "Manuelle"
        case .downloads: return "Téléchargements"
        case .volume: return "Volume externe"
        case .realtime: return "Temps réel"
        case .scheduled: return "Planifiée"
        case .retroHunt: return "Rétro-chasse"
        case .unknown: return "Autre"
        }
    }
}

extension JobState {
    public var label: String {
        switch self {
        case .queued: return "En attente"
        case .running: return "En cours"
        case .finished: return "Terminée"
        case .cancelled: return "Annulée"
        case .failed: return "Échec"
        case .unknown: return "Inconnu"
        }
    }
}

extension AlertKind {
    public var label: String {
        switch self {
        case .malware: return "Malware"
        case .suspicious: return "Fichier suspect"
        case .persistence: return "Persistance"
        case .device: return "Périphérique"
        case .network: return "Réseau"
        case .update: return "Mise à jour"
        case .system: return "Système"
        case .unknown: return "Autre"
        }
    }
}

extension AlertStatus {
    public var label: String {
        switch self {
        case .open: return "Ouverte"
        case .acknowledged: return "Vue"
        case .resolved: return "Résolue"
        case .unknown: return "Inconnu"
        }
    }
}

extension AlertAction {
    public var label: String {
        switch self {
        case .acknowledge: return "Marquer comme vue"
        case .quarantine: return "Mettre en quarantaine"
        case .allow: return "Autoriser"
        case .restore: return "Restaurer"
        case .trustDevice: return "Faire confiance"
        case .blockDevice: return "Bloquer"
        case .approvePersistence: return "Approuver"
        case .removePersistence: return "Supprimer l'élément"
        case .reportFalsePositive: return "Signaler un faux positif"
        case .dismiss: return "Ignorer"
        case .unknown: return "Action inconnue"
        }
    }

    /// Changes something irreversible-looking: ask for confirmation in the UI.
    public var isDestructive: Bool {
        switch self {
        case .quarantine, .removePersistence, .blockDevice:
            return true
        default:
            return false
        }
    }
}

extension DeviceKind {
    /// Section title (plural).
    public var label: String {
        switch self {
        case .volume: return "Volumes"
        case .hid: return "Claviers, souris et HID"
        case .usb: return "Autres périphériques USB"
        case .bluetooth: return "Bluetooth"
        case .networkInterface: return "Interfaces réseau"
        case .thunderbolt: return "Thunderbolt"
        case .wifiNetwork: return "Réseaux Wi-Fi"
        case .unknown: return "Autres"
        }
    }
}

extension DeviceTrust {
    public var label: String {
        switch self {
        case .unknown: return "Non vérifié"
        case .trusted: return "De confiance"
        case .blocked: return "Bloqué"
        }
    }
}

extension DeviceChange {
    public var label: String {
        switch self {
        case .new: return "Nouveau"
        case .connected: return "Connecté"
        case .disconnected: return "Déconnecté"
        case .unknown: return "Inconnu"
        }
    }
}

extension PersistenceKind {
    public var label: String {
        switch self {
        case .launchAgent: return "LaunchAgent"
        case .launchDaemon: return "LaunchDaemon"
        case .loginItem: return "Élément de connexion"
        case .backgroundItem: return "Élément d'arrière-plan"
        case .cron: return "Tâche cron"
        case .periodic: return "Script periodic"
        case .shellProfile: return "Profil shell"
        case .configurationProfile: return "Profil de configuration"
        case .browserExtension: return "Extension de navigateur"
        case .systemExtension: return "Extension système"
        case .kernelExtension: return "Extension du noyau"
        case .authorizationPlugin: return "Plugin d'autorisation"
        case .other: return "Autre"
        }
    }
}

extension PersistenceStatus {
    public var label: String {
        switch self {
        case .baseline: return "Présent à l'installation"
        case .new: return "Nouveau"
        case .approved: return "Approuvé"
        case .removed: return "Supprimé"
        case .quarantined: return "En quarantaine"
        case .unknown: return "Inconnu"
        }
    }
}

extension ComponentState {
    public var label: String {
        switch self {
        case .notInstalled: return "Non installé"
        case .installed: return "À jour"
        case .updateAvailable: return "Mise à jour disponible"
        case .updating: return "Mise à jour…"
        case .error: return "Erreur"
        case .disabled: return "Désactivé"
        case .needsUserAction: return "Action requise"
        case .unknown: return "Inconnu"
        }
    }
}

extension UpdateTarget {
    public var label: String {
        switch self {
        case .db: return "Base de menaces"
        case .components: return "Composants"
        case .app: return "Application"
        case .all: return "Tout"
        case .unknown: return "Inconnu"
        }
    }
}

extension ExtensionState {
    public var label: String {
        switch self {
        case .notInstalled: return "Non installée"
        case .installedDisabled: return "Installée mais désactivée"
        case .enabled: return "Activée"
        case .unknown: return "État inconnu"
        }
    }
}

extension ProtectionState {
    public var label: String {
        switch self {
        case .active: return "Protection active"
        case .paused: return "Protection en pause"
        case .degraded: return "Protection dégradée"
        case .unknown: return "État inconnu"
        }
    }
}

extension ErrorCode {
    public var label: String {
        switch self {
        case .badRequest: return "Requête invalide"
        case .notFound: return "Introuvable"
        case .permissionDenied: return "Permission refusée"
        case .authRequired: return "Autorisation administrateur requise"
        case .busy: return "Service occupé"
        case .unavailable: return "Indisponible"
        case .internalError: return "Erreur interne"
        case .unknown: return "Erreur"
        }
    }
}
