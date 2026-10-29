//! GDPR letters (pure): erasure request (art. 17 + objection art. 21(2)/(3) + art. 19 + art. 12(3)), formal
//! reminder, complaint to the supervisory authority. Wording adapted from the Datenanfragen.de templates
//! (CC0 1.0, github.com/datenanfragen/data/templates/{fr,en}).

use chrono::{DateTime, Datelike, Utc};
use pb_core::model::{BrokerInfo, IdentityProfile, RemovalRequest, RemovalStatus};

/// Letter language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Fr,
    En,
}

/// Top-level domains whose organisations get French letters (when the configured language is `fr`).
const FRENCH_TLDS: [&str; 4] = ["fr", "be", "lu", "ch"];

fn tld_of_host(host: &str) -> Option<String> {
    host.trim_end_matches('.')
        .rsplit('.')
        .next()
        .map(|s| s.to_ascii_lowercase())
}

fn host_of_url(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?;
    Some(host.split(':').next().unwrap_or(host))
}

/// French only for EU brokers whose email or website is under .fr/.be/.lu/.ch, when `language` is `fr`;
/// English otherwise.
pub fn language_for(
    language: &str,
    region: &str,
    email: Option<&str>,
    website: Option<&str>,
) -> Lang {
    if !language.eq_ignore_ascii_case("fr") || !region.eq_ignore_ascii_case("eu") {
        return Lang::En;
    }
    let mut tlds = Vec::new();
    if let Some(e) = email {
        if let Some((_, d)) = e.rsplit_once('@') {
            tlds.extend(tld_of_host(d));
        }
    }
    if let Some(w) = website.and_then(host_of_url) {
        tlds.extend(tld_of_host(w));
    }
    if tlds.iter().any(|t| FRENCH_TLDS.contains(&t.as_str())) {
        Lang::Fr
    } else {
        Lang::En
    }
}

/// Convenience for a broker.
pub fn language_for_broker(language: &str, b: &BrokerInfo) -> Lang {
    language_for(
        language,
        &b.region,
        b.email.as_deref(),
        b.website.as_deref(),
    )
}

/// Subject + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Letter {
    pub subject: String,
    pub body: String,
}

const MONTHS_FR: [&str; 12] = [
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
];
const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// `29 octobre 2026` / `29 October 2026` (UTC).
pub fn format_date(ts: i64, lang: Lang) -> String {
    let dt: DateTime<Utc> = DateTime::from_timestamp(ts, 0).unwrap_or_default();
    let m = dt.month0() as usize;
    match lang {
        Lang::Fr => format!(
            "{} {} {}",
            if dt.day() == 1 {
                "1er".to_string()
            } else {
                dt.day().to_string()
            },
            MONTHS_FR[m],
            dt.year()
        ),
        Lang::En => format!("{} {} {}", dt.day(), MONTHS_EN[m], dt.year()),
    }
}

fn clean(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}

/// Identification lines: only the filled fields; the birth date only when set.
pub fn identity_lines(p: &IdentityProfile, lang: Lang) -> Vec<String> {
    let mut v = Vec::new();
    let (name, mails, phones, addr, prev, birth) = match lang {
        Lang::Fr => (
            "Nom",
            "Adresse(s) e-mail",
            "Téléphone(s)",
            "Adresse postale",
            "Ancienne(s) adresse(s)",
            "Date de naissance",
        ),
        Lang::En => (
            "Name",
            "Email address(es)",
            "Phone number(s)",
            "Postal address",
            "Previous address(es)",
            "Date of birth",
        ),
    };
    let one_line = |s: &str| {
        clean(s)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !p.full_name.trim().is_empty() {
        v.push(format!("- {name} : {}", one_line(&p.full_name)));
    }
    let emails: Vec<String> = p
        .emails
        .iter()
        .map(|e| one_line(e))
        .filter(|e| !e.is_empty())
        .collect();
    if !emails.is_empty() {
        v.push(format!("- {mails} : {}", emails.join(", ")));
    }
    let ph: Vec<String> = p
        .phones
        .iter()
        .map(|e| one_line(e))
        .filter(|e| !e.is_empty())
        .collect();
    if !ph.is_empty() {
        v.push(format!("- {phones} : {}", ph.join(", ")));
    }
    if !p.postal_address.trim().is_empty() {
        v.push(format!("- {addr} : {}", one_line(&p.postal_address)));
    }
    let pa: Vec<String> = p
        .previous_addresses
        .iter()
        .map(|e| one_line(e))
        .filter(|e| !e.is_empty())
        .collect();
    if !pa.is_empty() {
        v.push(format!("- {prev} : {}", pa.join(" ; ")));
    }
    if !p.birth_date.trim().is_empty() {
        v.push(format!("- {birth} : {}", one_line(&p.birth_date)));
    }
    if lang == Lang::En {
        // English typography: no space before the colon.
        v = v.into_iter().map(|l| l.replacen(" : ", ": ", 1)).collect();
    }
    v
}

fn is_french_resident(p: &IdentityProfile) -> bool {
    p.country.trim().is_empty() || p.country.trim().eq_ignore_ascii_case("FR")
}

fn authority_phrase(p: &IdentityProfile, lang: Lang) -> &'static str {
    match (lang, is_french_resident(p)) {
        (Lang::Fr, true) => "la Commission nationale de l'informatique et des libertés (CNIL)",
        (Lang::Fr, false) => "l'autorité de contrôle compétente",
        (Lang::En, true) => "the French data protection authority (CNIL)",
        (Lang::En, false) => "the competent supervisory authority",
    }
}

/// Initial erasure + objection request.
pub fn erasure(p: &IdentityProfile, broker_name: &str, lang: Lang) -> Letter {
    let ids = identity_lines(p, lang).join("\n");
    let name = clean(&p.full_name);
    let authority = authority_phrase(p, lang);
    let broker = clean(broker_name);
    match lang {
        Lang::Fr => Letter {
            subject: "Demande d'effacement de données personnelles (article 17 du RGPD)".into(),
            body: format!(
                "À l'attention du délégué à la protection des données de {broker},\n\
\n\
Madame, Monsieur,\n\
\n\
Conformément à l'article 17 du règlement (UE) 2016/679 (RGPD), je vous demande d'effacer sans délai \
l'ensemble des données à caractère personnel me concernant que vous traitez, au sens de l'article 4, \
point 1, du RGPD.\n\
\n\
Si j'ai consenti au traitement de mes données, je retire ce consentement. En outre, conformément à \
l'article 21, paragraphes 2 et 3, du RGPD, je m'oppose au traitement de mes données à des fins de \
prospection, y compris au profilage lié à cette prospection : cette opposition n'a pas à être motivée \
et doit être suivie d'effet.\n\
\n\
Si vous avez communiqué mes données à des tiers, vous devez leur notifier cet effacement conformément \
à l'article 19 du RGPD ; je vous demande également de m'indiquer l'identité de ces destinataires.\n\
\n\
Ma demande vise tous les services et sociétés dont vous êtes le responsable du traitement au sens de \
l'article 4, point 7, du RGPD.\n\
\n\
Conformément à l'article 12, paragraphe 3, du RGPD, vous devez me confirmer l'effacement dans les \
meilleurs délais et en tout état de cause dans un délai d'un mois à compter de la réception de la \
présente demande. Si vous estimez ne pas pouvoir y donner suite, vous devez m'en indiquer les motifs \
dans le même délai.\n\
\n\
Pour me retrouver dans vos fichiers, voici les informations me concernant que vous êtes susceptible \
de détenir ; elles ne doivent être utilisées que pour traiter cette demande :\n\
{ids}\n\
\n\
À défaut de réponse dans ce délai, je me réserve le droit d'introduire une réclamation auprès de \
{authority} et d'exercer un recours juridictionnel.\n\
\n\
Je vous prie d'agréer, Madame, Monsieur, l'expression de mes salutations distinguées.\n\
\n\
{name}\n"
            ),
        },
        Lang::En => Letter {
            subject: "Request for erasure of personal data (Article 17 GDPR)".into(),
            body: format!(
                "To the Data Protection Officer of {broker},\n\
\n\
Dear Sir or Madam,\n\
\n\
Pursuant to Article 17 of Regulation (EU) 2016/679 (GDPR), I request the erasure without undue delay of \
all personal data concerning me, as defined in Article 4(1) GDPR, that you process.\n\
\n\
If I have given consent to the processing of my data, I hereby withdraw it. Furthermore, pursuant to \
Article 21(2) and (3) GDPR, I object to the processing of my personal data for direct marketing \
purposes, including profiling related to direct marketing; this objection requires no justification \
and must be complied with.\n\
\n\
If you have disclosed my personal data to third parties, you must communicate this erasure to each \
recipient in accordance with Article 19 GDPR; please also inform me about these recipients.\n\
\n\
This request covers every service and company for which you are the controller within the meaning of \
Article 4(7) GDPR.\n\
\n\
In accordance with Article 12(3) GDPR, please confirm the erasure without undue delay and in any event \
within one month of receipt of this request. If you do not intend to comply, you must inform me of the \
reasons within the same period.\n\
\n\
To identify me in your records, here is the information about me that you may hold; it must only be \
used to handle this request:\n\
{ids}\n\
\n\
Should I not receive a response within this period, I reserve the right to lodge a complaint with \
{authority} and to take legal action.\n\
\n\
Yours faithfully,\n\
\n\
{name}\n"
            ),
        },
    }
}

/// Formal reminder once the one-month deadline passed (two more weeks).
pub fn reminder(p: &IdentityProfile, broker_name: &str, sent_at: i64, lang: Lang) -> Letter {
    let ids = identity_lines(p, lang).join("\n");
    let name = clean(&p.full_name);
    let authority = authority_phrase(p, lang);
    let broker = clean(broker_name);
    let date = format_date(sent_at, lang);
    match lang {
        Lang::Fr => Letter {
            subject: "Relance : demande d'effacement de données personnelles (article 17 du RGPD)"
                .into(),
            body: format!(
                "À l'attention du délégué à la protection des données de {broker},\n\
\n\
Madame, Monsieur,\n\
\n\
Le {date}, je vous ai adressé une demande d'effacement de mes données à caractère personnel et \
d'opposition à leur traitement, en application des articles 17 et 21 du RGPD.\n\
\n\
Le délai d'un mois prévu par l'article 12, paragraphe 3, du RGPD est écoulé et je n'ai reçu aucune \
réponse satisfaisante.\n\
\n\
Je vous demande donc de nouveau d'y donner suite dans un délai de deux semaines à compter de la \
réception du présent message. À défaut, j'introduirai une réclamation auprès de {authority}.\n\
\n\
Pour rappel, informations permettant de m'identifier :\n\
{ids}\n\
\n\
Je vous prie d'agréer, Madame, Monsieur, l'expression de mes salutations distinguées.\n\
\n\
{name}\n"
            ),
        },
        Lang::En => Letter {
            subject: "Reminder: request for erasure of personal data (Article 17 GDPR)".into(),
            body: format!(
                "To the Data Protection Officer of {broker},\n\
\n\
Dear Sir or Madam,\n\
\n\
On {date}, I sent you a request for the erasure of my personal data and an objection to its \
processing pursuant to Articles 17 and 21 GDPR.\n\
\n\
The one-month period set by Article 12(3) GDPR has expired without a satisfactory response.\n\
\n\
I therefore ask you once more to comply within two weeks of receipt of this message. Otherwise, I will \
lodge a complaint with {authority}.\n\
\n\
As a reminder, information to identify me:\n\
{ids}\n\
\n\
Yours faithfully,\n\
\n\
{name}\n"
            ),
        },
    }
}

/// Complaint to the supervisory authority (CNIL for French residents).
pub fn complaint(
    p: &IdentityProfile,
    req: &RemovalRequest,
    broker_website: Option<&str>,
    lang: Lang,
) -> (String, String, String) {
    let french = is_french_resident(p);
    let (authority, url) = if french {
        (
            "CNIL".to_string(),
            "https://www.cnil.fr/fr/plaintes".to_string(),
        )
    } else {
        match lang {
            Lang::Fr => ("Autorité de contrôle compétente".to_string(), String::new()),
            Lang::En => ("Competent supervisory authority".to_string(), String::new()),
        }
    };
    let name = clean(&p.full_name);
    let contact = p
        .emails
        .iter()
        .map(|e| clean(e))
        .find(|e| !e.is_empty())
        .unwrap_or_default();
    let mut org = vec![clean(&req.broker_name)];
    if let Some(e) = &req.broker_email {
        org.push(clean(e));
    }
    if let Some(w) = broker_website {
        org.push(clean(w));
    }
    let org = org.join("\n");
    let sent = req.sent_at.map(|t| format_date(t, lang));
    let reminded = req.reminded_at.map(|t| format_date(t, lang));
    let refused = req.status == RemovalStatus::Refused;
    let text = match lang {
        Lang::Fr => {
            let mut facts = String::new();
            match &sent {
                Some(d) => facts.push_str(&format!(
                    "Le {d}, j'ai adressé à cet organisme une demande d'effacement de mes données à \
caractère personnel (article 17 du RGPD) et d'opposition à leur traitement à des fins de prospection \
(article 21 du RGPD)."
                )),
                None => facts.push_str(
                    "J'ai adressé à cet organisme une demande d'effacement de mes données à caractère \
personnel (article 17 du RGPD) et d'opposition à leur traitement (article 21 du RGPD).",
                ),
            }
            if let Some(r) = &reminded {
                facts.push_str(&format!(" Je l'ai relancé le {r}."));
            }
            if refused {
                facts.push_str(" L'organisme a refusé de faire droit à ma demande.");
            } else {
                facts.push_str(
                    " À ce jour, je n'ai reçu aucune réponse satisfaisante, alors que le délai d'un mois \
prévu par l'article 12, paragraphe 3, du RGPD est expiré.",
                );
            }
            format!(
                "Madame, Monsieur,\n\
\n\
J'introduis par la présente une réclamation, en application de l'article 77 du RGPD, à l'encontre \
de l'organisme suivant :\n\
{org}\n\
\n\
{facts}\n\
\n\
Je vous demande d'examiner cette situation et de veiller à ce que cet organisme se conforme à ma \
demande.\n\
\n\
Je joins à cette réclamation une copie de ma demande initiale et de ma relance, avec leurs dates \
d'envoi. Vous pouvez me contacter à l'adresse suivante : {contact}.\n\
\n\
Je vous remercie par avance de votre aide.\n\
\n\
Je vous prie d'agréer, Madame, Monsieur, l'expression de mes salutations distinguées.\n\
\n\
{name}\n"
            )
        }
        Lang::En => {
            let mut facts = String::new();
            match &sent {
                Some(d) => facts.push_str(&format!(
                    "On {d}, I sent this organisation a request for the erasure of my personal data \
(Article 17 GDPR) and an objection to its processing for direct marketing (Article 21 GDPR)."
                )),
                None => facts.push_str(
                    "I sent this organisation a request for the erasure of my personal data (Article 17 \
GDPR) and an objection to its processing (Article 21 GDPR).",
                ),
            }
            if let Some(r) = &reminded {
                facts.push_str(&format!(" I sent a reminder on {r}."));
            }
            if refused {
                facts.push_str(" The organisation refused to comply with my request.");
            } else {
                facts.push_str(
                    " To date I have not received a satisfactory response, although the one-month \
period of Article 12(3) GDPR has expired.",
                );
            }
            format!(
                "Dear Sir or Madam,\n\
\n\
I hereby lodge a complaint pursuant to Article 77 GDPR against the following organisation:\n\
{org}\n\
\n\
{facts}\n\
\n\
I ask you to examine this matter and to ensure that the organisation complies with my request.\n\
\n\
I attach a copy of my initial request and of my reminder, with their dates. You can contact me at: \
{contact}.\n\
\n\
Thank you in advance for your help.\n\
\n\
Yours faithfully,\n\
\n\
{name}\n"
            )
        }
    };
    (authority, url, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> IdentityProfile {
        IdentityProfile {
            full_name: "Camille Test".into(),
            emails: vec!["q@example.fr".into(), " ".into()],
            phones: vec![],
            postal_address: "1 rue de la Paix\n75002 Paris".into(),
            previous_addresses: vec![],
            birth_date: String::new(),
            country: "FR".into(),
        }
    }

    #[test]
    fn language_rule() {
        assert_eq!(
            language_for(
                "fr",
                "eu",
                Some("dpo@criteo.com"),
                Some("https://www.criteo.com/")
            ),
            Lang::En
        );
        assert_eq!(
            language_for(
                "fr",
                "eu",
                Some("dpo@sls-data.com"),
                Some("https://sls.fr/x")
            ),
            Lang::Fr
        );
        assert_eq!(
            language_for("fr", "eu", Some("dpo@exemple.be"), None),
            Lang::Fr
        );
        assert_eq!(
            language_for("fr", "us", Some("privacy@exemple.fr"), None),
            Lang::En
        );
        assert_eq!(
            language_for("en", "eu", Some("dpo@exemple.fr"), None),
            Lang::En
        );
        assert_eq!(
            language_for("FR", "EU", None, Some("https://user@host.lu:443/p")),
            Lang::Fr
        );
    }

    #[test]
    fn erasure_letters() {
        let fr = erasure(&me(), "SLS Data", Lang::Fr);
        assert!(fr.subject.contains("article 17"));
        assert!(fr.body.contains("article 21, paragraphes 2 et 3"));
        assert!(fr.body.contains("article 19"));
        assert!(fr.body.contains("délai d'un mois"));
        assert!(fr.body.contains("- Nom : Camille Test"));
        assert!(fr.body.contains("- Adresse(s) e-mail : q@example.fr\n"));
        assert!(fr
            .body
            .contains("- Adresse postale : 1 rue de la Paix, 75002 Paris"));
        assert!(!fr.body.contains("naissance"));
        assert!(!fr.body.contains("Téléphone"));
        assert!(fr.body.contains("(CNIL)"));
        assert!(fr.body.ends_with("Camille Test\n"));
        let mut p = me();
        p.birth_date = "1999-01-02".into();
        p.country = "DE".into();
        let en = erasure(&p, "Criteo", Lang::En);
        assert!(en.subject.starts_with("Request for erasure"));
        assert!(en.body.contains("- Date of birth: 1999-01-02"));
        assert!(en.body.contains("Article 21(2) and (3)"));
        assert!(en.body.contains("competent supervisory authority"));
    }

    #[test]
    fn reminder_and_dates() {
        assert_eq!(format_date(1_793_491_200, Lang::Fr), "1er novembre 2026");
        assert_eq!(format_date(1_793_491_200, Lang::En), "1 November 2026");
        let r = reminder(&me(), "X", 1_793_491_200, Lang::Fr);
        assert!(r.subject.starts_with("Relance"));
        assert!(r.body.contains("Le 1er novembre 2026"));
        assert!(r.body.contains("deux semaines"));
    }

    #[test]
    fn complaint_text() {
        let req = RemovalRequest {
            id: "r".into(),
            broker_id: "b".into(),
            broker_name: "Acme".into(),
            broker_email: Some("dpo@acme.com".into()),
            status: RemovalStatus::Escalated,
            created_at: 0,
            sent_at: Some(1_793_491_200),
            due_at: None,
            reminded_at: Some(1_793_491_200 + 31 * 86_400),
            closed_at: None,
            opt_out_url: None,
            draft_path: None,
            note: None,
            last_error: None,
        };
        let (auth, url, text) = complaint(&me(), &req, Some("https://acme.com"), Lang::Fr);
        assert_eq!(auth, "CNIL");
        assert_eq!(url, "https://www.cnil.fr/fr/plaintes");
        assert!(text.contains("article 77"));
        assert!(text.contains("Acme\ndpo@acme.com\nhttps://acme.com"));
        assert!(text.contains("Je l'ai relancé le 2 décembre 2026"));
        assert!(text.contains("q@example.fr"));
        let mut p = me();
        p.country = "BE".into();
        let (auth, url, _) = complaint(&p, &req, None, Lang::Fr);
        assert_eq!(auth, "Autorité de contrôle compétente");
        assert!(url.is_empty());
    }
}
