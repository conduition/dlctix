use bitcoin::Amount;

use common::{Intent, OutcomeOdds};
use dlctix::{Outcome, PayoutWeights, PlayerIndex};

use std::collections::BTreeMap;

pub(crate) fn compute_deposit_and_payout_weights<'i>(
    intents: &BTreeMap<PlayerIndex, &'i Intent>,
    odds: &OutcomeOdds,
    all_outcomes: impl IntoIterator<Item = Outcome>,
) -> (
    BTreeMap<PlayerIndex, Amount>,
    BTreeMap<Outcome, PayoutWeights>,
) {
    let mut outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::new();

    // All players for a given outcome are paid out equally.
    for (&player_index, intent) in intents {
        outcome_payouts
            .entry(intent.outcome)
            .or_default()
            .insert(player_index, 1);
    }

    // Count only outcomes which people have wagered on.
    let total_odds_weight: u64 = odds
        .iter()
        .filter_map(|(outcome, &weight)| outcome_payouts.get(outcome).map(|_| weight))
        .sum();

    // Compute the relative weights for each player to deposit.
    let deposit_weights: PayoutWeights = intents
        .iter()
        .map(|(&player_index, intent)| {
            let n_winners = outcome_payouts[&intent.outcome].len() as u64;
            let outcome_odds = odds[&intent.outcome];
            let weight = 100_000_000 * outcome_odds / total_odds_weight / n_winners;
            (player_index, weight)
        })
        .collect();

    // For any outcomes which nobody wagered on, all deposits will be refunded.
    for outcome in all_outcomes {
        if !outcome_payouts.contains_key(&outcome) {
            outcome_payouts.insert(outcome, deposit_weights.clone());
        }
    }

    // Start with the maximum possible pot by summing all players' budgets.
    let mut pot_total: Amount = intents.values().map(|intent| intent.budget).sum();

    let total_deposit_weight: u64 = deposit_weights.values().sum();
    for (player_index, intent) in intents {
        let weight = deposit_weights[player_index];
        let suggested_deposit_amount = pot_total * weight / total_deposit_weight;

        // If this player's deposit amount exceeds their budget, scale the pot down until
        if suggested_deposit_amount > intent.budget {
            pot_total = pot_total * intent.budget.to_sat() / suggested_deposit_amount.to_sat()
        }
    }

    let deposit_amounts = deposit_weights
        .into_iter()
        .map(|(player_index, weight)| {
            let deposit_amount = pot_total * weight / total_deposit_weight;
            (player_index, deposit_amount)
        })
        .collect();

    (deposit_amounts, outcome_payouts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_computations_two_players() {
        let intents = BTreeMap::from([
            (
                0,
                Intent {
                    outcome: Outcome::Attestation(0),
                    budget: Amount::from_sat(100_000),
                },
            ),
            (
                1,
                Intent {
                    outcome: Outcome::Attestation(1),
                    budget: Amount::from_sat(300_000),
                },
            ),
        ]);

        let odds = OutcomeOdds::from([
            (Outcome::Attestation(0), 1),
            (Outcome::Attestation(1), 2),
            (Outcome::Expiry, 1),
        ]);

        let all_outcomes = [
            Outcome::Attestation(0),
            Outcome::Attestation(1),
            Outcome::Attestation(2),
            Outcome::Expiry,
        ];

        let expected_deposit_amounts = BTreeMap::from([
            (0, Amount::from_sat(100_000)),
            (1, Amount::from_sat(200_000)),
        ]);
        let expected_outcome_payouts = BTreeMap::from([
            (Outcome::Attestation(0), PayoutWeights::from([(0, 1)])),
            (Outcome::Attestation(1), PayoutWeights::from([(1, 1)])),
            (
                Outcome::Attestation(2),
                PayoutWeights::from([(0, 33333333), (1, 66666666)]),
            ),
            (
                Outcome::Expiry,
                PayoutWeights::from([(0, 33333333), (1, 66666666)]),
            ),
        ]);

        let (deposit_amounts, outcome_payouts) =
            compute_deposit_and_payout_weights(&intents, &odds, all_outcomes);

        assert_eq!(deposit_amounts, expected_deposit_amounts);
        assert_eq!(outcome_payouts, expected_outcome_payouts);
    }

    #[test]
    fn test_weight_computations_three_players_with_equal_buy_in() {
        let intents = BTreeMap::from([
            (
                0,
                Intent {
                    outcome: Outcome::Attestation(0),
                    budget: Amount::from_sat(100_000),
                },
            ),
            (
                1,
                Intent {
                    outcome: Outcome::Attestation(1),
                    budget: Amount::from_sat(300_000),
                },
            ),
            (
                2,
                Intent {
                    outcome: Outcome::Attestation(1),
                    budget: Amount::from_sat(150_000),
                },
            ),
        ]);

        let odds = OutcomeOdds::from([
            (Outcome::Attestation(0), 1),
            (Outcome::Attestation(1), 2),
            (Outcome::Expiry, 1),
        ]);

        let all_outcomes = [
            Outcome::Attestation(0),
            Outcome::Attestation(1),
            Outcome::Attestation(2),
            Outcome::Expiry,
        ];

        let expected_deposit_amounts = BTreeMap::from([
            (0, Amount::from_sat(100_000)),
            (1, Amount::from_sat(100_000)),
            (2, Amount::from_sat(100_000)),
        ]);
        let expected_outcome_payouts = BTreeMap::from([
            // Player 0 wins alone
            (Outcome::Attestation(0), PayoutWeights::from([(0, 1)])),
            // Player 1 and 2 win together, splitting the prize
            (
                Outcome::Attestation(1),
                PayoutWeights::from([(1, 1), (2, 1)]),
            ),
            // Unexpected outcome; all players refunded
            (
                Outcome::Attestation(2),
                PayoutWeights::from([(0, 33333333), (1, 33333333), (2, 33333333)]),
            ),
            (
                Outcome::Expiry,
                PayoutWeights::from([(0, 33333333), (1, 33333333), (2, 33333333)]),
            ),
        ]);

        let (deposit_amounts, outcome_payouts) =
            compute_deposit_and_payout_weights(&intents, &odds, all_outcomes);

        assert_eq!(deposit_amounts, expected_deposit_amounts);
        assert_eq!(outcome_payouts, expected_outcome_payouts);
    }

    #[test]
    fn test_weight_computations_five_players() {
        let intents = BTreeMap::from([
            (
                0,
                Intent {
                    outcome: Outcome::Attestation(0),
                    budget: Amount::from_sat(100_000),
                },
            ),
            (
                1,
                Intent {
                    outcome: Outcome::Attestation(0),
                    budget: Amount::from_sat(200_000),
                },
            ),
            (
                2,
                Intent {
                    outcome: Outcome::Attestation(1),
                    budget: Amount::from_sat(150_000),
                },
            ),
            (
                3,
                Intent {
                    outcome: Outcome::Attestation(1),
                    budget: Amount::from_sat(300_000),
                },
            ),
            (
                4,
                Intent {
                    outcome: Outcome::Attestation(2),
                    budget: Amount::from_sat(500_000),
                },
            ),
        ]);

        // Odds weight sum: 8
        let odds = OutcomeOdds::from([
            (Outcome::Attestation(0), 1),
            (Outcome::Attestation(1), 2),
            (Outcome::Attestation(2), 5),
        ]);

        let all_outcomes = [
            Outcome::Attestation(0),
            Outcome::Attestation(1),
            Outcome::Attestation(2),
            Outcome::Expiry,
        ];

        // Pot total: 800k
        let expected_deposit_amounts = BTreeMap::from([
            // Players 0 and 1 deposit 50k, receiving 400k each on victory (1:8 odds)
            (0, Amount::from_sat(50_000)),
            (1, Amount::from_sat(50_000)),
            // Players 2 and 3 deposit 100k, receiving 400k each on victory (1:4 odds)
            (2, Amount::from_sat(100_000)),
            (3, Amount::from_sat(100_000)),
            // Player 4 deposits 500k, receiving 800k on victory (8:5 odds)
            (4, Amount::from_sat(500_000)),
        ]);

        let expected_outcome_payouts = BTreeMap::from([
            // Player 0 and 1 and win together, splitting the prize
            (
                Outcome::Attestation(0),
                PayoutWeights::from([(0, 1), (1, 1)]),
            ),
            // Player 2 and 3 win together, splitting the prize
            (
                Outcome::Attestation(1),
                PayoutWeights::from([(2, 1), (3, 1)]),
            ),
            // Player 4 wins alone
            (Outcome::Attestation(2), PayoutWeights::from([(4, 1)])),
            // Unexpected outcome; all players refunded
            (
                Outcome::Expiry,
                PayoutWeights::from([
                    (0, 6_250_000),
                    (1, 6_250_000),
                    (2, 12_500_000),
                    (3, 12_500_000),
                    (4, 62_500_000),
                ]),
            ),
        ]);

        let (deposit_amounts, outcome_payouts) =
            compute_deposit_and_payout_weights(&intents, &odds, all_outcomes);

        assert_eq!(deposit_amounts, expected_deposit_amounts);
        assert_eq!(outcome_payouts, expected_outcome_payouts);
    }
}
