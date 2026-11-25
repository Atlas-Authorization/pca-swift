import Foundation

// Refinement over the typed outcome space. The typed `PCAIntentOmega` is the one implementation of the cell arithmetic; these entry points read
// and return it, and run the same refinement as the JSON ones.
public extension PCAIntentRefine {
    /// The typed outcome space with one verb's dimension refined (the input is untouched).
    static func refineOmega(typed omega: PCAIntentOmega.Omega, _ r: Refinement) throws -> PCAIntentOmega.Omega {
        try PCAIntentOmega.omegaFromJson(try refineOmega(PCAIntentOmega.omegaToJson(omega), r))
    }

    /// The value-space region an observation was about, in the typed space it was recorded in.
    static func regionOfObservation(typed omega: PCAIntentOmega.Omega, _ o: PCAIntentLearner.Observation) throws -> JSONValue {
        try regionOfObservation(try WalletOmega(PCAIntentOmega.omegaToJson(omega)), o)
    }
}
