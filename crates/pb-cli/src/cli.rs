//! Command-line definition (clap derive, French help).

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// `parabellum` — client of the parabellumd daemon.
#[derive(Debug, Parser)]
#[command(
    name = "parabellum",
    version,
    about = "Client en ligne de commande de Parabellum, l'antivirus open source pour macOS",
    propagate_version = true
)]
pub struct Cli {
    /// Sortie JSON brute (données renvoyées par le daemon) au lieu des tableaux.
    #[arg(long, global = true)]
    pub json: bool,
    /// Socket du daemon (défaut : $PARABELLUM_SOCKET, sinon /var/run/parabellum.sock).
    #[arg(long, global = true, value_name = "CHEMIN")]
    pub socket: Option<PathBuf>,
    /// Délai maximal d'une requête, en secondes.
    #[arg(long, global = true, value_name = "SECONDES", default_value_t = 25)]
    pub timeout: u64,
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Parse an argument vector (first item = program name) without exiting on error.
    pub fn try_parse_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::try_parse_from(args)
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// État de la protection.
    Status,
    /// Analyser des fichiers ou dossiers (code de sortie 1 si des menaces sont trouvées).
    Scan(ScanArgs),
    /// Analyses récentes.
    Jobs {
        /// Nombre maximal d'analyses affichées.
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Détail d'une analyse.
    Job {
        /// Identifiant de l'analyse.
        id: String,
    },
    /// Annuler une analyse en cours ou en attente.
    Cancel {
        /// Identifiant de l'analyse.
        id: String,
    },
    /// Alertes (ouvertes par défaut).
    Alerts {
        /// Inclure les alertes résolues.
        #[arg(long)]
        all: bool,
        /// Nombre maximal d'alertes.
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Appliquer une action à une alerte (acknowledge, quarantine, allow, restore, trust-device,
    /// block-device, approve-persistence, remove-persistence, report-false-positive, dismiss).
    Resolve {
        /// Numéro de l'alerte.
        alert_id: i64,
        /// Action à appliquer.
        action: String,
    },
    /// Quarantaine : lister (défaut), ajouter, restaurer, supprimer.
    Quarantine {
        #[command(subcommand)]
        action: Option<QuarantineCmd>,
    },
    /// Signaler un faux positif (l'empreinte est ajoutée à la liste d'autorisation locale).
    Fp {
        /// SHA-256 du fichier.
        sha256: String,
        /// Chemin du fichier concerné.
        #[arg(long)]
        path: Option<String>,
        /// Remarque libre.
        #[arg(long)]
        note: Option<String>,
    },
    /// Éléments de persistance (LaunchAgents, LaunchDaemons, éléments d'ouverture…).
    #[command(args_conflicts_with_subcommands = true)]
    Persistence {
        /// Seulement les nouveaux éléments (non approuvés).
        #[arg(long)]
        new: bool,
        #[command(subcommand)]
        action: Option<PersistenceCmd>,
    },
    /// Périphériques connus.
    #[command(args_conflicts_with_subcommands = true)]
    Devices {
        /// Filtrer par type (volume, hid, usb, bluetooth, network-interface, thunderbolt, wifi-network).
        #[arg(long)]
        kind: Option<String>,
        #[command(subcommand)]
        action: Option<DevicesCmd>,
    },
    /// Lancer une mise à jour (base, composants, application ou tout).
    Update {
        /// Cible de la mise à jour.
        #[arg(value_enum, default_value_t = UpdateArg::All)]
        target: UpdateArg,
        /// Ne pas attendre la fin.
        #[arg(long)]
        no_wait: bool,
    },
    /// Composants tiers (ClamAV, osquery, dnscrypt-proxy, LuLu…).
    Components {
        #[command(subcommand)]
        action: Option<ComponentsCmd>,
    },
    /// Blocage DNS global : activer, désactiver, état.
    Dns {
        #[arg(value_enum, default_value_t = DnsArg::Status)]
        state: DnsArg,
    },
    /// État du blocage des publicités (uBlock Origin Lite + DNS).
    Adblock,
    /// Configuration (TOML).
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Mettre en pause la protection temps réel.
    Pause {
        /// Durée en minutes.
        minutes: u32,
    },
    /// Reprendre la protection temps réel.
    Resume,
    /// Rapport hebdomadaire.
    Report {
        /// 0 = semaine en cours, 1 = semaine dernière…
        #[arg(long, default_value_t = 0)]
        week: u32,
    },
    /// Ré-analyser les fichiers vus récemment avec la base actuelle.
    RetroHunt {
        /// Fenêtre en jours.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Afficher les événements du daemon en continu (Ctrl-C pour quitter).
    Watch,
    /// Vérifier que le daemon répond.
    Ping,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Fichiers ou dossiers à analyser.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    /// Forcer ClamAV pour cette analyse.
    #[arg(long, conflicts_with = "no_clamav")]
    pub clamav: bool,
    /// Ne pas utiliser ClamAV pour cette analyse.
    #[arg(long)]
    pub no_clamav: bool,
    /// Ne pas parcourir les sous-dossiers.
    #[arg(long)]
    pub no_recursive: bool,
    /// Rendre la main immédiatement (afficher seulement l'identifiant).
    #[arg(long)]
    pub no_wait: bool,
}

#[derive(Debug, Subcommand)]
pub enum QuarantineCmd {
    /// Lister les fichiers en quarantaine.
    List,
    /// Mettre un fichier en quarantaine.
    Add {
        /// Fichier à isoler.
        path: PathBuf,
    },
    /// Restaurer un fichier.
    Restore {
        /// Identifiant de l'entrée.
        id: String,
        /// Autoriser aussi ce fichier à l'avenir.
        #[arg(long)]
        allow: bool,
    },
    /// Supprimer définitivement un fichier en quarantaine.
    Delete {
        /// Identifiant de l'entrée.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PersistenceCmd {
    /// Approuver (conserver) un élément.
    Approve {
        /// Identifiant de l'élément.
        id: String,
    },
    /// Retirer un élément (déchargement + quarantaine du plist et du programme).
    Remove {
        /// Identifiant de l'élément.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DevicesCmd {
    /// Faire confiance à un périphérique.
    Trust {
        /// Identifiant du périphérique.
        id: String,
    },
    /// Bloquer un périphérique.
    Block {
        /// Identifiant du périphérique.
        id: String,
    },
    /// Oublier la décision (retour à « inconnu »).
    Forget {
        /// Identifiant du périphérique.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ComponentsCmd {
    /// Lister les composants (défaut).
    List,
    /// Installer ou réinstaller un composant.
    Install {
        /// Nom du composant (clamav, osquery, dnscrypt-proxy…).
        name: String,
    },
    /// Activer / désactiver la mise à jour automatique d'un composant.
    Auto {
        /// Nom du composant.
        name: String,
        #[arg(value_enum)]
        state: OnOff,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Afficher la configuration (TOML).
    Get,
    /// Remplacer la configuration par un fichier TOML (validé).
    Set {
        /// Fichier TOML.
        file: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UpdateArg {
    Db,
    Components,
    App,
    All,
}

impl From<UpdateArg> for pb_core::model::UpdateTarget {
    fn from(u: UpdateArg) -> Self {
        use pb_core::model::UpdateTarget as T;
        match u {
            UpdateArg::Db => T::Db,
            UpdateArg::Components => T::Components,
            UpdateArg::App => T::App,
            UpdateArg::All => T::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsArg {
    On,
    Off,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

/// Parse a snake_case enum of pb-core from user input (`-` accepted for `_`).
pub fn parse_wire_enum<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    let norm = s.trim().to_ascii_lowercase().replace('-', "_");
    serde_json::from_value(serde_json::Value::String(norm)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use pb_core::model::{AlertAction, DeviceKind};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("parabellum").chain(args.iter().copied()))
    }

    #[test]
    fn definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_args() {
        let c = parse(&["scan", "/a", "/b", "--clamav", "--no-wait"]).unwrap();
        match c.command {
            Command::Scan(s) => {
                assert_eq!(s.paths.len(), 2);
                assert!(s.clamav && s.no_wait && !s.no_clamav);
            }
            _ => panic!(),
        }
        assert!(parse(&["scan"]).is_err());
        assert!(parse(&["scan", "/a", "--clamav", "--no-clamav"]).is_err());
    }

    #[test]
    fn global_flags_anywhere() {
        let c = parse(&["alerts", "--all", "--json", "--limit", "5"]).unwrap();
        assert!(c.json);
        assert!(matches!(
            c.command,
            Command::Alerts {
                all: true,
                limit: 5
            }
        ));
        let c = parse(&["--socket", "/tmp/s", "--timeout", "3", "ping"]).unwrap();
        assert_eq!(c.socket.unwrap(), PathBuf::from("/tmp/s"));
        assert_eq!(c.timeout, 3);
    }

    #[test]
    fn nested_commands() {
        assert!(matches!(
            parse(&["quarantine"]).unwrap().command,
            Command::Quarantine { action: None }
        ));
        assert!(matches!(
            parse(&["quarantine", "restore", "x", "--allow"])
                .unwrap()
                .command,
            Command::Quarantine {
                action: Some(QuarantineCmd::Restore { allow: true, .. })
            }
        ));
        assert!(matches!(
            parse(&["persistence", "--new"]).unwrap().command,
            Command::Persistence {
                new: true,
                action: None
            }
        ));
        assert!(matches!(
            parse(&["persistence", "remove", "abc"]).unwrap().command,
            Command::Persistence {
                action: Some(PersistenceCmd::Remove { .. }),
                ..
            }
        ));
        assert!(matches!(
            parse(&["devices", "--kind", "hid"]).unwrap().command,
            Command::Devices {
                kind: Some(_),
                action: None
            }
        ));
        assert!(matches!(
            parse(&["devices", "forget", "vol:1"]).unwrap().command,
            Command::Devices {
                action: Some(DevicesCmd::Forget { .. }),
                ..
            }
        ));
        assert!(matches!(
            parse(&["update"]).unwrap().command,
            Command::Update {
                target: UpdateArg::All,
                no_wait: false
            }
        ));
        assert!(matches!(
            parse(&["update", "db", "--no-wait"]).unwrap().command,
            Command::Update {
                target: UpdateArg::Db,
                no_wait: true
            }
        ));
        assert!(matches!(
            parse(&["dns", "off"]).unwrap().command,
            Command::Dns { state: DnsArg::Off }
        ));
        assert!(matches!(
            parse(&["dns"]).unwrap().command,
            Command::Dns {
                state: DnsArg::Status
            }
        ));
        assert!(matches!(
            parse(&["components", "auto", "clamav", "off"])
                .unwrap()
                .command,
            Command::Components {
                action: Some(ComponentsCmd::Auto {
                    state: OnOff::Off,
                    ..
                })
            }
        ));
        assert!(matches!(
            parse(&["config", "set", "f.toml"]).unwrap().command,
            Command::Config {
                action: ConfigCmd::Set { .. }
            }
        ));
        assert!(matches!(
            parse(&["retro-hunt", "--days", "7"]).unwrap().command,
            Command::RetroHunt { days: 7 }
        ));
        assert!(matches!(
            parse(&["report", "--week", "1"]).unwrap().command,
            Command::Report { week: 1 }
        ));
        assert!(parse(&["pause"]).is_err());
        assert!(parse(&["resolve", "x", "acknowledge"]).is_err());
    }

    #[test]
    fn wire_enums() {
        assert_eq!(
            parse_wire_enum::<AlertAction>("remove-persistence"),
            Some(AlertAction::RemovePersistence)
        );
        assert_eq!(
            parse_wire_enum::<AlertAction>("Acknowledge"),
            Some(AlertAction::Acknowledge)
        );
        assert_eq!(
            parse_wire_enum::<DeviceKind>("wifi-network"),
            Some(DeviceKind::WifiNetwork)
        );
        assert_eq!(parse_wire_enum::<DeviceKind>("nope"), None);
    }
}
