use thorn_core::{BotClassification, BotScore, BotSignal};

pub fn compute_bot_score(signals: Vec<BotSignal>) -> BotScore {
    if signals.is_empty() {
        return BotScore {
            score: 0.0,
            signals,
            classification: BotClassification::Human,
        };
    }

    let score = signals.iter().map(|s| s.confidence).sum::<f64>() / signals.len() as f64;

    let has_conway = signals
        .iter()
        .any(|s| matches!(s.kind, thorn_core::SignalKind::ConwayInfrastructure));

    let classification = if has_conway {
        BotClassification::ConwayAutomaton
    } else if score > 0.8 {
        BotClassification::ConfirmedBot
    } else if score > 0.6 {
        BotClassification::LikelyBot
    } else if score > 0.4 {
        BotClassification::Uncertain
    } else if score > 0.2 {
        BotClassification::LikelyHuman
    } else {
        BotClassification::Human
    };

    BotScore {
        score,
        signals,
        classification,
    }
}
