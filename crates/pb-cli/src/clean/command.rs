//! `parabellum clean scan|apply` (local, as the user).

use super::{apply, scan, CleanEnv, ALL_CATEGORIES};
use crate::cli::Cli;
use crate::commands::{CliError, Output, EXIT_ERROR, EXIT_OK, EXIT_THREATS};
use clap::{Args, Subcommand, ValueEnum};
use pb_core::model::*;
use std::io::Read;
use std::path::PathBuf;

/// Max size of a plan file.
const MAX_PLAN: u64 = 16 * 1024 * 1024;

#[derive(Debug, Args)]
pub struct CleanArgs {
    #[command(subcommand)]
    pub action: CleanCmd,
}

#[derive(Debug, Subcommand)]
pub enum CleanCmd {
    /// Lister ce qui peut être nettoyé (rien n'est modifié).
    Scan {
        /// Catégories à analyser (toutes par défaut).
        #[arg(long = "category", value_enum)]
        categories: Vec<CategoryArg>,
    },
    /// Nettoyer : un plan JSON (--plan, « - » pour l'entrée standard) ou les éléments cochés d'office des
    /// catégories données. Sans --yes, simple simulation.
    Apply {
        /// Plan JSON {"items":[{"category":"caches","path":"…"}],"permanent":["logs"]}.
        #[arg(long, value_name = "FICHIER", conflicts_with = "categories")]
        plan: Option<PathBuf>,
        /// Catégories (éléments cochés d'office uniquement).
        #[arg(long = "category", value_enum)]
        categories: Vec<CategoryArg>,
        /// Supprimer définitivement au lieu de mettre à la corbeille (catégories de --category).
        #[arg(long)]
        permanent: bool,
        /// Simuler sans rien modifier.
        #[arg(long)]
        dry_run: bool,
        /// Confirmer le nettoyage.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CategoryArg {
    Caches,
    BrowserCaches,
    DeveloperCaches,
    Logs,
    Downloads,
    LargeFiles,
    AppLeftovers,
    Trash,
}

impl From<CategoryArg> for CleanCategory {
    fn from(c: CategoryArg) -> Self {
        match c {
            CategoryArg::Caches => CleanCategory::Caches,
            CategoryArg::BrowserCaches => CleanCategory::BrowserCaches,
            CategoryArg::DeveloperCaches => CleanCategory::DeveloperCaches,
            CategoryArg::Logs => CleanCategory::Logs,
            CategoryArg::Downloads => CleanCategory::Downloads,
            CategoryArg::LargeFiles => CleanCategory::LargeFiles,
            CategoryArg::AppLeftovers => CleanCategory::AppLeftovers,
            CategoryArg::Trash => CleanCategory::Trash,
        }
    }
}

/// French size, decimal units like Finder: `1,2 Go`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["octets", "Ko", "Mo", "Go", "To"];
    if n < 1000 {
        return format!("{n} octets");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{:.1} {}", v, UNITS[u]).replace('.', ",")
}

fn read_plan(path: &PathBuf) -> Result<CleanPlan, CliError> {
    let mut text = String::new();
    if path.as_os_str() == "-" {
        std::io::stdin().take(MAX_PLAN).read_to_string(&mut text)?;
    } else {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_PLAN {
            return Err(CliError::Usage("plan trop volumineux".into()));
        }
        text = std::fs::read_to_string(path)?;
    }
    serde_json::from_str(&text).map_err(|e| CliError::Usage(format!("plan invalide : {e}")))
}

fn emit<T: serde::Serialize>(
    cli: &Cli,
    io: &mut Output<'_>,
    v: &T,
    human: impl FnOnce(&T) -> String,
) -> Result<(), CliError> {
    if cli.json {
        let s = serde_json::to_string_pretty(v).map_err(|e| CliError::Usage(e.to_string()))?;
        writeln!(io.out, "{s}")?;
    } else {
        write!(io.out, "{}", human(v))?;
    }
    Ok(())
}

pub fn format_scan(r: &CleanScanReport) -> String {
    let mut o = format!(
        "{} récupérables (cochés d'office) sur {} trouvés\n",
        human_size(r.reclaimable_size),
        human_size(r.total_size)
    );
    for c in &r.categories {
        o.push_str(&format!(
            "\n{} — {} ({} cochés)\n",
            c.title,
            human_size(c.size),
            human_size(c.selected_size)
        ));
        if let Some(e) = &c.error {
            o.push_str(&format!("  ! {e}\n"));
        }
        for i in c.items.iter().take(8) {
            o.push_str(&format!(
                "  [{}] {:>10}  {}{}\n",
                if i.selected { "x" } else { " " },
                human_size(i.size),
                i.name,
                i.note
                    .as_deref()
                    .map(|n| format!(" — {n}"))
                    .unwrap_or_default()
            ));
        }
        if c.items.len() > 8 {
            o.push_str(&format!("  … et {} autre(s)\n", c.items.len() - 8));
        }
    }
    for w in &r.warnings {
        o.push_str(&format!("attention : {w}\n"));
    }
    o
}

pub fn format_apply(r: &CleanApplyReport) -> String {
    let mut o = String::new();
    if r.dry_run {
        let total: u64 = r.results.iter().map(|x| x.bytes).sum();
        o.push_str(&format!(
            "Simulation : {} élément(s), {} (relance avec --yes pour nettoyer).\n",
            r.results
                .iter()
                .filter(|x| x.outcome == CleanOutcome::WouldClean)
                .count(),
            human_size(total)
        ));
    } else {
        o.push_str(&format!(
            "{} élément(s) nettoyé(s) : {} libérés, {} mis à la corbeille.\n",
            r.cleaned,
            human_size(r.freed_bytes),
            human_size(r.trashed_bytes)
        ));
    }
    for x in &r.results {
        if let Some(m) = &x.message {
            o.push_str(&format!("  {} : {m}\n", x.path));
        }
    }
    o
}

pub fn run(cli: &Cli, io: &mut Output<'_>, args: &CleanArgs) -> Result<i32, CliError> {
    let env = CleanEnv::system().map_err(CliError::Usage)?;
    match &args.action {
        CleanCmd::Scan { categories } => {
            let only: Vec<CleanCategory> = categories.iter().map(|c| (*c).into()).collect();
            let r = scan(&env, &only);
            emit(cli, io, &r, format_scan)?;
            Ok(EXIT_OK)
        }
        CleanCmd::Apply {
            plan,
            categories,
            permanent,
            dry_run,
            yes,
        } => {
            let plan = match plan {
                Some(p) => read_plan(p)?,
                None => {
                    if categories.is_empty() {
                        return Err(CliError::Usage(
                            "indique --plan ou au moins une --category".into(),
                        ));
                    }
                    let only: Vec<CleanCategory> = categories.iter().map(|c| (*c).into()).collect();
                    plan_of_selected(&scan(&env, &only), *permanent)
                }
            };
            let simulate = *dry_run || !*yes;
            let r = apply(&env, &plan, simulate);
            emit(cli, io, &r, format_apply)?;
            Ok(if r.failed > 0 {
                EXIT_THREATS
            } else if r.results.is_empty() && !plan.items.is_empty() {
                EXIT_ERROR
            } else {
                EXIT_OK
            })
        }
    }
}

/// Plan made of the preselected items of a scan.
pub fn plan_of_selected(r: &CleanScanReport, permanent: bool) -> CleanPlan {
    let mut plan = CleanPlan::default();
    for c in &r.categories {
        for i in c.items.iter().filter(|i| i.selected && !i.in_use) {
            plan.items.push(CleanPlanItem {
                category: c.category,
                path: i.path.clone(),
            });
        }
        if permanent && c.trashable {
            plan.permanent.push(c.category);
        }
    }
    plan
}

/// Every category, for help texts and tests.
pub fn all_categories() -> &'static [CleanCategory] {
    &ALL_CATEGORIES
}
