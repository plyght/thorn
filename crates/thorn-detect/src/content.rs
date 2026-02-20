use thorn_core::{BotSignal, SignalKind};

pub fn analyze_content(body: &str, title: &str, headings: &[String]) -> Vec<BotSignal> {
    let mut signals = Vec::new();

    let title_lower = title.to_lowercase();
    let ai_title_phrases = [
        "ultimate guide",
        "everything you need to know",
        "complete guide",
        "step by step",
        "best practices",
        "in today's",
    ];
    let separator_count = title.matches(" | ").count() + title.matches(" - ").count();
    let title_hits = ai_title_phrases
        .iter()
        .filter(|&&p| title_lower.contains(p))
        .count();

    if title.len() > 60 && (separator_count >= 2 || title_hits >= 1) {
        signals.push(BotSignal {
            kind: SignalKind::AiGeneratedContent,
            confidence: (0.4 + title_hits as f64 * 0.1).min(0.7),
            evidence: format!(
                "title keyword-stuffed: {} chars, {} separators, {} ai phrases",
                title.len(),
                separator_count,
                title_hits
            ),
        });
    }

    if let Some(sig) = check_structural_homogeneity(body, headings) {
        signals.push(sig);
    }

    if let Some(sig) = check_ai_text_patterns(body) {
        signals.push(sig);
    }

    signals
}

fn check_structural_homogeneity(body: &str, headings: &[String]) -> Option<BotSignal> {
    let paragraphs: Vec<&str> = body
        .split("\n\n")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();

    if paragraphs.len() < 3 || headings.len() < 2 {
        return None;
    }

    let lengths: Vec<f64> = paragraphs.iter().map(|p| p.len() as f64).collect();
    let n = lengths.len() as f64;
    let mean = lengths.iter().sum::<f64>() / n;

    if mean < 20.0 {
        return None;
    }

    let variance = lengths.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean;

    let heading_levels: Vec<usize> = headings
        .iter()
        .map(|h| {
            let t = h.trim_start();
            if t.starts_with("### ") {
                3
            } else if t.starts_with("## ") {
                2
            } else if t.starts_with("# ") {
                1
            } else {
                0
            }
        })
        .collect();

    let non_zero: Vec<usize> = heading_levels.iter().copied().filter(|&l| l > 0).collect();

    let perfect_hierarchy = if non_zero.len() >= 2 {
        let min_l = *non_zero.iter().min().unwrap();
        let max_l = *non_zero.iter().max().unwrap();
        let distinct: std::collections::HashSet<usize> = non_zero.iter().copied().collect();
        max_l > min_l && distinct.len() == (max_l - min_l + 1)
    } else {
        false
    };

    let cv_confidence = if cv < 0.1 {
        0.9
    } else if cv < 0.2 {
        0.75
    } else if cv < 0.3 {
        0.6
    } else {
        return None;
    };

    let confidence = (cv_confidence + if perfect_hierarchy { 0.1_f64 } else { 0.0_f64 }).min(1.0);
    let evidence = format!(
        "paragraph CV={:.3} (mean={:.0}, n={}), perfect_hierarchy={}",
        cv,
        mean,
        paragraphs.len(),
        perfect_hierarchy
    );

    Some(BotSignal {
        kind: SignalKind::StructuralHomogeneity,
        confidence,
        evidence,
    })
}

fn check_ai_text_patterns(body: &str) -> Option<BotSignal> {
    if body.len() < 100 {
        return None;
    }

    let mut sub_signals: Vec<(f64, String)> = Vec::new();
    let text_lower = body.to_lowercase();

    let total = body.len() as f64;
    let mut freq = [0u64; 256];
    for b in body.bytes() {
        freq[b as usize] += 1;
    }
    let entropy: f64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();

    if (3.5..=4.2).contains(&entropy) {
        let dist = (entropy - 3.85_f64).abs();
        let conf = (0.65 - dist * 0.35).max(0.3);
        sub_signals.push((
            conf,
            format!("char entropy={:.3} bits (AI band 3.5-4.2)", entropy),
        ));
    }

    let sentences: Vec<usize> = body
        .split(|c| c == '.' || c == '!' || c == '?')
        .map(|s| s.trim())
        .filter(|s| s.split_whitespace().count() >= 3)
        .map(|s| s.split_whitespace().count())
        .collect();

    if sentences.len() >= 5 {
        let sn = sentences.len() as f64;
        let mean_wc = sentences.iter().sum::<usize>() as f64 / sn;
        let variance_wc = sentences
            .iter()
            .map(|&x| (x as f64 - mean_wc).powi(2))
            .sum::<f64>()
            / sn;

        if variance_wc < 15.0 {
            let conf = if variance_wc < 5.0 {
                0.80
            } else if variance_wc < 10.0 {
                0.65
            } else {
                0.50
            };
            sub_signals.push((
                conf,
                format!(
                    "sentence-length variance={:.2} (low burstiness)",
                    variance_wc
                ),
            ));
        }
    }

    let contractions = [
        "don't",
        "can't",
        "won't",
        "it's",
        "i'm",
        "we're",
        "they're",
        "isn't",
        "aren't",
        "wasn't",
        "weren't",
        "hasn't",
        "haven't",
        "hadn't",
        "doesn't",
        "didn't",
        "couldn't",
        "wouldn't",
        "shouldn't",
        "i've",
        "we've",
        "they've",
        "i'd",
        "we'd",
        "they'd",
        "i'll",
        "we'll",
        "they'll",
    ];
    let contraction_count = contractions
        .iter()
        .filter(|&&c| text_lower.contains(c))
        .count();
    let word_count = body.split_whitespace().count();

    if word_count > 100 && contraction_count == 0 {
        sub_signals.push((0.55, format!("no contractions in {} words", word_count)));
    } else if word_count > 200 && contraction_count <= 1 {
        sub_signals.push((
            0.40,
            format!(
                "sparse contractions ({}) in {} words",
                contraction_count, word_count
            ),
        ));
    }

    let ai_phrases = [
        "it's important to note",
        "it is important to note",
        "in conclusion",
        "let's delve",
        "let us delve",
        "comprehensive",
        "leverage",
        "utilize",
        "facilitate",
        "in today's world",
        "in today's",
        "it's worth noting",
        "it is worth noting",
        "furthermore",
        "moreover",
        "in summary",
        "to summarize",
        "this article will",
        "we will explore",
    ];
    let hits: Vec<&str> = ai_phrases
        .iter()
        .filter(|&&p| text_lower.contains(p))
        .copied()
        .collect();

    if hits.len() >= 2 {
        let conf = (0.35 + hits.len() as f64 * 0.08).min(0.85);
        sub_signals.push((
            conf,
            format!("AI phrases: {}", hits[..hits.len().min(3)].join(", ")),
        ));
    } else if hits.len() == 1 {
        sub_signals.push((0.30, format!("AI phrase: {}", hits[0])));
    }

    if sub_signals.len() < 2 {
        return None;
    }

    let avg = sub_signals.iter().map(|(c, _)| c).sum::<f64>() / sub_signals.len() as f64;
    let confidence = (avg + (sub_signals.len() as f64 - 1.0) * 0.05).min(1.0);
    let evidence = sub_signals
        .into_iter()
        .map(|(_, e)| e)
        .collect::<Vec<_>>()
        .join("; ");

    Some(BotSignal {
        kind: SignalKind::AiGeneratedContent,
        confidence,
        evidence,
    })
}
