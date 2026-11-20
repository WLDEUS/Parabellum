import Foundation

/// Everything in "Vie privée" as search documents: erasure requests, the broker catalogue, breaches,
/// e-mail aliases. Field names are the ones `champ:valeur` filters use (French, no accents).
public enum PrivacySearch {
    public enum Kind: String, CaseIterable, Sendable, Identifiable {
        case request, broker, breach, alias

        public var id: String { rawValue }

        public var label: String {
            switch self {
            case .request: return "Demande RGPD"
            case .broker: return "Courtier"
            case .breach: return "Fuite"
            case .alias: return "Alias"
            }
        }

        public var pluralLabel: String {
            switch self {
            case .request: return "Demandes"
            case .broker: return "Courtiers"
            case .breach: return "Fuites"
            case .alias: return "Alias"
            }
        }

        public var symbol: String {
            switch self {
            case .request: return "envelope.badge.shield.half.filled"
            case .broker: return "building.2"
            case .breach: return "drop.triangle"
            case .alias: return "at"
            }
        }
    }

    /// Words a `type:` filter accepts for each kind.
    public static let kindAliases: [String: [String]] = [
        Kind.request.rawValue: ["demande", "demandes", "rgpd", "effacement"],
        Kind.broker.rawValue: ["courtier", "courtiers", "catalogue"],
        Kind.breach.rawValue: ["fuite", "fuites"],
        Kind.alias.rawValue: ["alias"],
    ]

    /// Filters shown as hints in the UI.
    public static let filterHints = [
        "type:demande", "type:fuite", "statut:attente", "reponse:formulaire", "courtier:", "email:", "donnees:password",
    ]

    /// Reference in the subject of every letter (`PB-1a2b3c4d`), as the daemon builds it.
    public static func reference(requestId: String) -> String {
        let hex = requestId.lowercased().filter { $0.isHexDigit }
        return "PB-" + String(hex.prefix(8))
    }

    public static func documents(
        requests: [RemovalRequest],
        brokers: [BrokerInfo],
        breaches: [BreachFinding],
        aliases: [EmailAlias]
    ) -> [SearchDocument] {
        var docs: [SearchDocument] = []
        for r in requests {
            var fields: [String: String] = [
                "courtier": r.brokerName,
                "statut": r.status.label,
                "ref": reference(requestId: r.id),
            ]
            fields["email"] = r.brokerEmail
            fields["note"] = r.note
            fields["erreur"] = r.lastError
            fields["formulaire"] = r.optOutUrl
            let reply = [r.lastReplyKind?.label, r.lastReplySummary].compactMap { $0 }.joined(separator: " — ")
            if !reply.isEmpty { fields["reponse"] = reply }
            let date = (r.lastReplyAt ?? r.sentAt ?? r.createdAt)
            docs.append(SearchDocument(
                kind: Kind.request.rawValue, key: r.id, title: r.brokerName, subtitle: r.status.label,
                date: Date(unixSeconds: date), fields: fields
            ))
        }
        for b in brokers {
            var fields: [String: String] = [
                "categorie": b.category,
                "region": PrivacyLabels.region(b.region),
                "source": b.source,
            ]
            fields["email"] = b.email
            fields["site"] = b.website
            fields["formulaire"] = b.optOutUrl
            docs.append(SearchDocument(
                kind: Kind.broker.rawValue, key: b.id, title: b.name,
                subtitle: "\(b.category) · \(PrivacyLabels.region(b.region))", date: nil, fields: fields
            ))
        }
        for f in breaches {
            var fields: [String: String] = [
                "email": f.email,
                "donnees": f.dataClasses.joined(separator: ", "),
            ]
            fields["date"] = f.breachDate
            if f.new { fields["etat"] = "nouvelle" }
            docs.append(SearchDocument(
                kind: Kind.breach.rawValue, key: f.id, title: f.breach, subtitle: f.email,
                date: f.breachDate.flatMap(parseDay) ?? Date(unixSeconds: f.firstSeen), fields: fields
            ))
        }
        for a in aliases {
            docs.append(SearchDocument(
                kind: Kind.alias.rawValue, key: a.id, title: a.email, subtitle: a.label,
                date: a.createdDate,
                fields: [
                    "libelle": a.label,
                    "fournisseur": a.provider.label,
                    "etat": a.active ? "actif" : "désactivé",
                ]
            ))
        }
        return docs
    }

    public static func index(
        requests: [RemovalRequest],
        brokers: [BrokerInfo],
        breaches: [BreachFinding],
        aliases: [EmailAlias]
    ) -> SearchIndex {
        SearchIndex(
            documents(requests: requests, brokers: brokers, breaches: breaches, aliases: aliases),
            kindAliases: kindAliases
        )
    }

    private static func parseDay(_ text: String) -> Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: String(text.prefix(10)))
    }
}
