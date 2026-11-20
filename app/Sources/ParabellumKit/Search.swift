import Foundation

/// Local full-text search in the spirit of Elasticsearch, in memory, without dependencies:
/// - case- and accent-insensitive ("societe" finds "Société"),
/// - prefix matching while typing ("acx" finds "Acxiom"),
/// - typo tolerance with Elasticsearch's AUTO fuzziness (1 edit from 3 letters, 2 from 6: "axciom"),
/// - `champ:valeur` filters (`statut:attente`, `type:fuite`), `"exact phrase"`, `-excluded`,
/// - relevance ranking (exact > prefix > fuzzy; title > subtitle > other fields), then recency.
///
/// Every free term must match (AND), like Elasticsearch's `operator: and`.
public enum TextFold {
    /// Lowercased, accents removed ("Réf. Élysée" -> "ref. elysee").
    public static func fold(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: Locale(identifier: "fr_FR"))
            .lowercased()
    }

    /// Folded words: letters and digits, everything else separates.
    public static func tokens(_ text: String) -> [String] {
        fold(text)
            .split(whereSeparator: { !($0.isLetter || $0.isNumber) })
            .map(String.init)
    }

    /// Ranges of the words of `text` whose folded form is in `words` (for highlighting).
    public static func ranges(in text: String, matching words: Set<String>) -> [Range<String.Index>] {
        guard !words.isEmpty else { return [] }
        var out: [Range<String.Index>] = []
        var start: String.Index?
        var index = text.startIndex
        func close(_ end: String.Index) {
            if let s = start {
                let range = s..<end
                if words.contains(fold(String(text[range]))) {
                    out.append(range)
                }
                start = nil
            }
        }
        while index < text.endIndex {
            let c = text[index]
            if c.isLetter || c.isNumber {
                if start == nil { start = index }
            } else {
                close(index)
            }
            index = text.index(after: index)
        }
        close(text.endIndex)
        return out
    }

    /// Damerau-Levenshtein distance (optimal string alignment), `nil` once it exceeds `limit`.
    public static func distance(_ a: String, _ b: String, limit: Int) -> Int? {
        let x = Array(a), y = Array(b)
        if abs(x.count - y.count) > limit { return nil }
        if x.isEmpty { return y.count <= limit ? y.count : nil }
        if y.isEmpty { return x.count <= limit ? x.count : nil }
        var previous2 = [Int](repeating: 0, count: y.count + 1)
        var previous = Array(0...y.count)
        var current = [Int](repeating: 0, count: y.count + 1)
        for i in 1...x.count {
            current[0] = i
            var rowMin = current[0]
            for j in 1...y.count {
                let cost = x[i - 1] == y[j - 1] ? 0 : 1
                var v = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
                if i > 1, j > 1, x[i - 1] == y[j - 2], x[i - 2] == y[j - 1] {
                    v = min(v, previous2[j - 2] + 1)
                }
                current[j] = v
                rowMin = min(rowMin, v)
            }
            if rowMin > limit { return nil }
            (previous2, previous, current) = (previous, current, previous2)
        }
        let d = previous[y.count]
        return d <= limit ? d : nil
    }

    /// Elasticsearch `fuzziness: AUTO`: 0 edits up to 2 letters, 1 up to 5, then 2.
    public static func allowedEdits(_ term: String) -> Int {
        switch term.count {
        case 0...2: return 0
        case 3...5: return 1
        default: return 2
        }
    }
}

/// Something searchable: a title, a subtitle and named fields (`statut`, `email`…), all free text.
public struct SearchDocument: Sendable, Hashable, Identifiable {
    public let kind: String
    public let key: String
    public let title: String
    public let subtitle: String
    public let date: Date?
    /// Field name (lowercase, no accents: `statut`, `reponse`…) -> text.
    public let fields: [String: String]

    public var id: String { "\(kind):\(key)" }

    public init(kind: String, key: String, title: String, subtitle: String, date: Date?, fields: [String: String]) {
        self.kind = kind
        self.key = key
        self.title = title
        self.subtitle = subtitle
        self.date = date
        self.fields = fields
    }
}

public struct SearchHit: Sendable, Hashable, Identifiable {
    public let document: SearchDocument
    public let score: Double
    /// Folded document words that matched (pass to `TextFold.ranges` to highlight).
    public let matchedWords: Set<String>
    /// Best matching field outside title/subtitle (`(name, text)`), to show why the document came up.
    public let snippet: SearchSnippet?

    public var id: String { document.id }
}

public struct SearchSnippet: Sendable, Hashable {
    public let field: String
    public let text: String
}

/// A parsed query: free terms, phrases, exclusions and `field:value` filters.
public struct SearchQuery: Sendable, Hashable {
    public var terms: [String] = []
    public var phrases: [String] = []
    public var excluded: [String] = []
    public var filters: [Filter] = []

    public struct Filter: Sendable, Hashable {
        public let field: String
        public let value: String
    }

    public var isEmpty: Bool { terms.isEmpty && phrases.isEmpty && excluded.isEmpty && filters.isEmpty }

    public init() {}

    /// `acxiom statut:"en attente" -refus "accusé de réception"`.
    public static func parse(_ text: String) -> SearchQuery {
        var q = SearchQuery()
        var chunks: [String] = []
        var buffer = ""
        var inQuotes = false
        for c in text {
            if c == "\"" || c == "«" || c == "»" {
                inQuotes.toggle()
                buffer.append("\"")
            } else if c.isWhitespace && !inQuotes {
                if !buffer.isEmpty { chunks.append(buffer); buffer = "" }
            } else {
                buffer.append(c)
            }
        }
        if !buffer.isEmpty { chunks.append(buffer) }

        for chunk in chunks {
            var c = chunk
            let negated = c.hasPrefix("-") && c.count > 1
            if negated { c.removeFirst() }
            if let colon = c.firstIndex(of: ":"), colon != c.startIndex, !negated {
                let field = TextFold.fold(String(c[..<colon]))
                let value = String(c[c.index(after: colon)...]).replacingOccurrences(of: "\"", with: "")
                if field.allSatisfy({ $0.isLetter }) && !value.isEmpty {
                    q.filters.append(Filter(field: field, value: TextFold.fold(value)))
                    continue
                }
            }
            if c.hasPrefix("\"") {
                let phrase = TextFold.tokens(c).joined(separator: " ")
                if !phrase.isEmpty {
                    if negated { q.excluded.append(contentsOf: TextFold.tokens(c)) } else { q.phrases.append(phrase) }
                }
                continue
            }
            let words = TextFold.tokens(c)
            if negated { q.excluded.append(contentsOf: words) } else { q.terms.append(contentsOf: words) }
        }
        return q
    }
}

/// In-memory index: build it once per data change, query it on every keystroke.
public struct SearchIndex: Sendable {
    private struct Field: Sendable {
        let name: String
        let weight: Double
        let text: String
        let words: [String]
        /// Words joined by single spaces (phrase matching).
        let joined: String
    }

    private struct Entry: Sendable {
        let document: SearchDocument
        let fields: [Field]
    }

    private let entries: [Entry]

    public static let titleField = "titre"
    public static let subtitleField = "sous-titre"
    /// `type:` filter: matched against the document kind and these aliases.
    public static let kindField = "type"

    private let kindAliases: [String: [String]]

    /// `kindAliases`: words a `type:` filter accepts for each kind (`["request": ["demande", "rgpd"]]`).
    public init(_ documents: [SearchDocument], kindAliases: [String: [String]] = [:]) {
        self.kindAliases = kindAliases.mapValues { $0.map(TextFold.fold) }
        entries = documents.map { doc in
            var fields: [Field] = []
            func add(_ name: String, _ weight: Double, _ text: String) {
                let words = TextFold.tokens(text)
                guard !words.isEmpty else { return }
                fields.append(Field(name: name, weight: weight, text: text, words: words, joined: words.joined(separator: " ")))
            }
            add(Self.titleField, 3, doc.title)
            add(Self.subtitleField, 2, doc.subtitle)
            for (name, text) in doc.fields.sorted(by: { $0.key < $1.key }) {
                add(TextFold.fold(name), 1, text)
            }
            return Entry(document: doc, fields: fields)
        }
    }

    public var count: Int { entries.count }

    /// Hits for `text`, best first. An empty query returns nothing; a query made only of filters returns
    /// every document that passes them, most recent first.
    public func search(_ text: String, limit: Int = 200) -> [SearchHit] {
        let query = SearchQuery.parse(text)
        guard !query.isEmpty else { return [] }
        var hits: [SearchHit] = []
        for entry in entries {
            if let hit = match(entry, query) { hits.append(hit) }
        }
        hits.sort { a, b in
            if a.score != b.score { return a.score > b.score }
            let da = a.document.date ?? .distantPast, db = b.document.date ?? .distantPast
            if da != db { return da > db }
            return a.document.title.localizedCompare(b.document.title) == .orderedAscending
        }
        return Array(hits.prefix(limit))
    }

    /// Best match of one query word in one field: score in 0...1 and the document word that matched.
    private func best(_ term: String, in field: Field) -> (Double, String)? {
        var result: (Double, String)?
        let edits = TextFold.allowedEdits(term)
        for word in field.words {
            let score: Double
            if word == term {
                score = 1
            } else if term.count >= 2 && word.hasPrefix(term) {
                score = 0.75
            } else if edits > 0, let d = TextFold.distance(term, word, limit: edits) {
                score = d == 1 ? 0.5 : 0.35
            } else {
                continue
            }
            if result == nil || score > result!.0 { result = (score, word) }
            if score == 1 { break }
        }
        return result
    }

    private func match(_ entry: Entry, _ q: SearchQuery) -> SearchHit? {
        // Filters: `type:` on the kind, otherwise any field whose name starts with the filter name.
        for filter in q.filters {
            if filter.field == Self.kindField {
                let kind = entry.document.kind
                let accepted = [TextFold.fold(kind)] + (kindAliases[kind] ?? [])
                guard accepted.contains(where: { $0.hasPrefix(filter.value) }) else { return nil }
                continue
            }
            let fields = entry.fields.filter { $0.name.hasPrefix(filter.field) }
            let valueWords = TextFold.tokens(filter.value)
            guard !fields.isEmpty,
                  fields.contains(where: { f in
                      valueWords.allSatisfy { v in f.words.contains { $0.hasPrefix(v) } }
                  })
            else { return nil }
        }
        // Exclusions: no exact or prefix occurrence anywhere.
        for word in q.excluded {
            if entry.fields.contains(where: { f in f.words.contains { $0 == word || $0.hasPrefix(word) } }) {
                return nil
            }
        }
        var score = 0.0
        var matched = Set<String>()
        var snippetField: (Double, Field)?
        for term in q.terms {
            var bestTerm: (Double, Field, String)?
            for field in entry.fields {
                guard let found = best(term, in: field) else { continue }
                let (s, word) = found
                let weighted = s * field.weight
                if bestTerm == nil || weighted > bestTerm!.0 { bestTerm = (weighted, field, word) }
            }
            guard let found = bestTerm else { return nil }
            let (s, field, word) = found
            score += s
            matched.insert(word)
            // Collect the other occurrences in every field for highlighting.
            for f in entry.fields {
                for w in f.words where w == word || (term.count >= 2 && w.hasPrefix(term)) {
                    matched.insert(w)
                }
            }
            if field.name != Self.titleField && field.name != Self.subtitleField,
               snippetField == nil || s > snippetField!.0 {
                snippetField = (s, field)
            }
        }
        for phrase in q.phrases {
            guard let field = entry.fields.first(where: { $0.joined.contains(phrase) }) else { return nil }
            score += 2 * field.weight
            matched.formUnion(phrase.split(separator: " ").map(String.init))
            if field.name != Self.titleField && field.name != Self.subtitleField && snippetField == nil {
                snippetField = (2, field)
            }
        }
        let snippet = snippetField.map { SearchSnippet(field: $0.1.name, text: $0.1.text) }
        return SearchHit(document: entry.document, score: score, matchedWords: matched, snippet: snippet)
    }
}
