#ifndef __TRUSTED_AI_HASH_CONSISTENCY_SNARK__
#define __TRUSTED_AI_HASH_CONSISTENCY_SNARK__

#include <zkdoc/src/trusted_ai_nizk.hpp>

// *************** TOP LEVEL FUNCTIONS *********************** //

SnarkProof multi_hash_consistency_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const std::vector<FieldT>& x,
    FieldT r
);

bool multi_hash_consistency_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& proof
);

// ********************************************************** //

SnarkProof multi_hash_consistency_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const std::vector<FieldT>& x,
    FieldT r
)
{
    snark_pp::init_public_params();
    SnarkProof snarkproof;

    ProverMessage statement;
    auto ck = read_commitment_key(COMM_KEY_FILE);
    auto cm = compute_commitment(ck, x, r);

    Protoboard<FieldT> pb;
    size_t h = sizeof(TrustedAI::partial_hash_sizes)/sizeof(size_t);
    pb_variable_array<FieldT> pb_multi_hashes;
    pb_variable_array<FieldT> pb_x;

    pb_multi_hashes.allocate(pb, h, "multi_hashes");
    allocate_slot(pb_x, x.size(), slot_size, "pb_x");
    multi_hash_consistency_gadget<FieldT> hash_gadget(pb, pb_x, pb_multi_hashes, "hash_gadget");

    pb_x.fill_with_field_elements(pb, pb_x);
    hash_gadget.generate_r1cs_witness();
    pb.set_input_sizes(h);

    auto pkey = read_proving_key(MULTIHASH_KEY_PK);
    std::vector<FieldT> randomness, multi_hashes;
    randomness.emplace_back(r);
    multi_hashes = pb_multi_hashes.get_vals(pb);

    ProofT proof = r1cs_adaptive_snark_prover<snark_pp>(
        pkey,
        pb.primary_input(),
        pb.auxiliary_input(),
        randomness,
        1,
        slot_size);

    statement.fieldVec = multi_hashes;
    statement.commVec.emplace_back(cm);
    statement.proof = proof;
    statement.containsProof = true;

    snarkproof.emplace_back(statement);
    return snarkproof;
}







#endif