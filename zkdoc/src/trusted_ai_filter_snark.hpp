#ifndef __TRUSTED_AI_FILTER_SNARK__
#define __TRUSTED_AI_FILTER_SNARK__

#include <zkdoc/src/trusted_ai_nizk.hpp>
#include <zkdoc/src/trusted_ai_simultaneous_permutation_snark.hpp>

#include <numeric>


// ****************** TOP LEVEL FUNCTIONS ********************************** //

typedef struct {
    VecVecT data;
    std::vector<FieldT> randomness;

    size_t size() const { return data[0].size(); };

} DatasetT;

typedef struct {
    std::vector<FieldT> data;
    FieldT randomness;

    size_t size() const { return data.size(); };
} VectorT;



SnarkProof filter_dataset_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const DatasetT& source,
    const VectorT& f,
    const DatasetT& dest 
);    

bool filter_dataset_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& snarkproof
);

SnarkProof selection_dataset_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const DatasetT& source,
    const QueryT& query,
    const VectorT& f
);

bool selection_dataset_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& snarkproof
);


SnarkProof aggregate_dataset_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const DatasetT& sourceA,
    const DatasetT& sourceB,
    const DatasetT& destC
);



bool aggregate_dataset_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& snarkproof
);
// ********************************************************************** //

SnarkProof filter_dataset_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const DatasetT& source,
    const VectorT& f,
    const DatasetT& dest)
{
    snark_pp::init_public_params();

    // read the commitment key
    auto ck = read_commitment_key(COMM_KEY_FILE);

    // compute commitments for initial statement
    auto cm_source = compute_comm_list(ck, source.data, source.randomness);
    auto cm_dest = compute_comm_list(ck, dest.data, dest.randomness);
    auto cm_f = compute_commitment(ck, f.data, f.randomness);

    SnarkProof snarkproof;
    ProverMessage statement;
    statement.commVec = cm_source;
    statement.commVec.emplace_back(cm_f);
    statement.commVec.insert(statement.commVec.end(), cm_dest.begin(), cm_dest.end());
    hash_chain.absorb(toString(statement));
    snarkproof.emplace_back(statement);

    // generate verifier randomness
    // We need random coefficients alpha_0,...,alpha_{k-1} summing to 1
    // We will generate random k-1 coefficients, and set the last one accordingly
    size_t k = cm_source.size();
    std::vector<FieldT> alpha = hash_chain.squeeze(k-1);
    FieldT sum = std::accumulate(alpha.begin(), alpha.end(), FieldT::zero());
    alpha.emplace_back(FieldT::one() - sum);

    CommT cm_x = compute_linear_combination(alpha, cm_source);
    CommT cm_y = compute_linear_combination(alpha, cm_dest);
    std::vector<FieldT> x = compute_linear_combination(alpha, source.data);
    std::vector<FieldT> y = compute_linear_combination(alpha, dest.data);
    FieldT rx = compute_linear_combination(alpha, source.randomness);
    FieldT ry = compute_linear_combination(alpha, dest.randomness);

    protoboard<FieldT> pb;
    size_t n = source.size() - 1;

    pb_variable_array<FieldT> var_x, var_f, var_y, var_X, var_Y, var_delta;
    allocate_slot(pb, var_x, n+1, slot_size, "var_x");
    allocate_slot(pb, var_f, n, slot_size, "var_f");
    allocate_slot(pb, var_y, n+1, slot_size, "var_y");
    allocate_slot(pb, var_X, n, slot_size, "var_X");
    allocate_slot(pb, var_Y, n, slot_size, "var_Y");
    allocate_slot(pb, var_delta, n, slot_size, "var_delta");

    cp_filter_gadget<FieldT> filter_gadget(pb, var_x, var_f, var_y, var_X, var_Y, var_delta, "filter-gadget");
    filter_gadget.generate_r1cs_constraints();

    var_x.fill_with_field_elements(pb, x);
    var_y.fill_with_field_elements(pb, y);
    var_f.fill_with_field_elements(pb, f.data);

    filter_gadget.generate_r1cs_witness();
    std::vector<FieldT> X = var_X.get_vals(pb);
    std::vector<FieldT> Y = var_Y.get_vals(pb);
    std::vector<FieldT> delta = var_delta.get_vals(pb);

    // choose randomness 
    auto rX = FieldT::random_element();
    auto rY = FieldT::random_element();
    auto rD = FieldT::random_element();

    // compute remaining commitments
    auto cm_X = compute_commitment(ck, X, rX);
    auto cm_Y = compute_commitment(ck, Y, rY);
    auto cm_delta = compute_commitment(ck, delta, rD);

    // generate proof for filter gadget
    auto pkfilter = read_proving_key(pkfilename);
    std::vector<CommT> comms = {cm_x, cm_f, cm_y, cm_X, cm_Y, cm_delta};
    std::vector<FieldT> randomness = {rx, f.randomness, ry, rX, rY, rD};

    auto proof = r1cs_adaptive_snark_prover(
        pkfilter,
        pb.primary_input(),
        pb.auxiliary_input(),
        randomness,
        6,
        slot_size
    );

    // make reduced statement
    ProverMessage reduced_statement;
    reduced_statement.commVec = comms;
    reduced_statement.proof = proof;
    reduced_statement.containsProof = true;
    hash_chain.absorb(toString(reduced_statement));
    snarkproof.emplace_back(reduced_statement);


    // run the simultaneous permutation sub-protocol
    VecVecT left = {X, f.data};
    VecVecT right = {Y, delta};
    std::vector<FieldT> rand_left = {rX, f.randomness};
    std::vector<FieldT> rand_right = {rY, rD};

    SnarkProof subproof = simultaneous_permutation_snark_prover(PERM_KEY_PK, hash_chain, n, left, right, rand_left, rand_right);
    snarkproof.insert(snarkproof.end(), subproof.begin(), subproof.end());

    return snarkproof;
}

bool filter_dataset_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& snarkproof)
{
    snark_pp::init_public_params();

    ProverMessage statement = snarkproof[0];
    hash_chain.absorb(toString(statement));

    size_t k = (statement.commVec.size() - 1)/2;

    std::vector<CommT> cm_source(statement.commVec.begin(), statement.commVec.begin()+k);
    std::vector<CommT> cm_dest(statement.commVec.begin() + k + 1, statement.commVec.end());
    CommT cm_f = statement.commVec[k];

    // generate verifier challenge
    std::vector<FieldT> alpha = hash_chain.squeeze(k-1);
    FieldT sum = std::accumulate(alpha.begin(), alpha.end(), FieldT::zero());
    alpha.emplace_back(FieldT::one() - sum);

    // compute reduced statement
    CommT cm_x = compute_linear_combination(alpha, cm_source);
    CommT cm_y = compute_linear_combination(alpha, cm_dest);

    // get the reduced statement from the proof
    ProverMessage reduced_statement = snarkproof[1];

    // exit if computed statement is inconsistent from proof statement
    if ((cm_x != reduced_statement.commVec[0]) || (cm_y != reduced_statement.commVec[2]) || (cm_f != reduced_statement.commVec[1]))
    {
        log_message("Computed reduced statement not consistent");
        return false;
    }

    // verify the snark proof
    if (!reduced_statement.containsProof)
    {
        log_message("Malformed SNARK proof");
        return false;
    }

    auto vkfilter = read_verification_key(vkfilename);
    std::vector<FieldT> primary_input;

    if (!r1cs_adaptive_snark_verifier(
        vkfilter,
        primary_input,
        reduced_statement.commVec,
        6,
        slot_size,
        reduced_statement.proof
    )) {
        log_message("SNARK proof verification failed");
        return false;
    }   

    hash_chain.absorb(toString(reduced_statement));
    SnarkProof subproof(snarkproof.begin()+2, snarkproof.end());
    bool ret = simultaneous_permutation_snark_verifier(PERM_KEY_VK, hash_chain, slot_size, subproof);

    if (ret)
        log_message("Proof Verified Successfully");
    else
        log_message("Proof Verification Failed");

    return ret;
}


SnarkProof aggregate_dataset_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const DatasetT& sourceA,
    const DatasetT& sourceB,
    const DatasetT& destC
) 
{
    snark_pp::init_public_params();

    // read the commitment key
    auto ck = read_commitment_key(COMM_KEY_FILE);

    // compute commitments for initial statement
    auto cm_source_A = compute_comm_list(ck, sourceA.data, sourceA.randomness);
    auto cm_source_B = compute_comm_list(ck, sourceB.data, sourceB.randomness);
    auto cm_dest = compute_comm_list(ck, destC.data, destC.randomness);


    SnarkProof snarkproof;
    ProverMessage statement;
    statement.commVec = cm_source_A;
    statement.commVec.insert(statement.commVec.end(), cm_source_B.begin(), cm_source_B.end());
    statement.commVec.insert(statement.commVec.end(), cm_dest.begin(), cm_dest.end());
    hash_chain.absorb(toString(statement));
    snarkproof.emplace_back(statement);

    // generate verifier randomness
    // We need random coefficients alpha_0,...,alpha_{k-1} summing to 1
    // We will generate random k-1 coefficients, and set the last one accordingly
    size_t k = cm_source_A.size();
    std::vector<FieldT> alpha = hash_chain.squeeze(k-1);
    FieldT sum = std::accumulate(alpha.begin(), alpha.end(), FieldT::zero());
    alpha.emplace_back(FieldT::one() - sum);

    CommT cm_x = compute_linear_combination(alpha, cm_source_A);
    CommT cm_y = compute_linear_combination(alpha, cm_source_B);
    CommT cm_z = compute_linear_combination(alpha, cm_dest);

    std::vector<FieldT> x = compute_linear_combination(alpha, sourceA.data);
    std::vector<FieldT> y = compute_linear_combination(alpha, sourceB.data);
    std::vector<FieldT> z = compute_linear_combination(alpha, destC.data);
    FieldT rx = compute_linear_combination(alpha, sourceA.randomness);
    FieldT ry = compute_linear_combination(alpha, sourceB.randomness);
    FieldT rz = compute_linear_combination(alpha, destC.randomness);

    protoboard<FieldT> pb;
    size_t n = sourceA.size() - 1;

    pb_variable_array<FieldT> var_x, var_y, var_z, var_XY, var_rhosigma, var_Zext, var_deltaext;
    allocate_slot(pb, var_x, n+1, slot_size, "var_x");
    allocate_slot(pb, var_y, n+1, slot_size, "var_y");
    allocate_slot(pb, var_z, n+1, slot_size, "var_z");
    allocate_slot(pb, var_XY, 2*n, slot_size, "var_XY");
    allocate_slot(pb, var_rhosigma, 2*n, slot_size, "var_rhosigma");
    allocate_slot(pb, var_Zext, 2*n, slot_size, "var_Zext");
    allocate_slot(pb, var_deltaext, 2*n, slot_size, "var_deltaext");


    cp_aggregate_gadget<FieldT> aggregate_gadget(pb, var_x, var_y, var_z, var_XY, var_rhosigma, var_Zext, var_deltaext, "aggregate-gadget");
    aggregate_gadget.generate_r1cs_constraints();

    var_x.fill_with_field_elements(pb, x);
    var_y.fill_with_field_elements(pb, y);
    var_z.fill_with_field_elements(pb, z);

    aggregate_gadget.generate_r1cs_witness();
    std::vector<FieldT> XY = var_XY.get_vals(pb);
    std::vector<FieldT> rhosigma = var_rhosigma.get_vals(pb);
    std::vector<FieldT> Zext = var_Zext.get_vals(pb);
    std::vector<FieldT> deltaext = var_deltaext.get_vals(pb);

    // choose randomness 
    auto r_XY = FieldT::random_element();
    auto r_rhosigma = FieldT::random_element();
    auto r_Zext = FieldT::random_element();
    auto r_deltaext = FieldT::random_element();

    // compute remaining commitments
    auto cm_XY = compute_commitment(ck, XY, r_XY);
    auto cm_rhosigma = compute_commitment(ck, rhosigma, r_rhosigma);
    auto cm_Zext = compute_commitment(ck, Zext, r_Zext);
    auto cm_deltaext = compute_commitment(ck, deltaext, r_deltaext);

    // generate proof for filter gadget
    auto pkfilter = read_proving_key(pkfilename);
    std::vector<CommT> comms = {cm_x, cm_y, cm_z, cm_XY, cm_rhosigma, cm_Zext, cm_deltaext};
    std::vector<FieldT> randomness = {rx, ry, rz, r_XY, r_rhosigma, r_Zext, r_deltaext};

    auto proof = r1cs_adaptive_snark_prover(
        pkfilter,
        pb.primary_input(),
        pb.auxiliary_input(),
        randomness,
        7,
        slot_size
    );

    // make reduced statement
    ProverMessage reduced_statement;
    reduced_statement.commVec = comms;
    reduced_statement.proof = proof;
    reduced_statement.containsProof = true;
    hash_chain.absorb(toString(reduced_statement));
    snarkproof.emplace_back(reduced_statement);


    // run the simultaneous permutation sub-protocol
    VecVecT left = {XY, rhosigma};
    VecVecT right = {Zext, deltaext};
    std::vector<FieldT> rand_left = {r_XY, r_rhosigma};
    std::vector<FieldT> rand_right = {r_Zext, r_deltaext};

    SnarkProof subproof = simultaneous_permutation_snark_prover(ROM_PERM_KEY_PK, hash_chain, slot_size, left, right, rand_left, rand_right);
    snarkproof.insert(snarkproof.end(), subproof.begin(), subproof.end());

    return snarkproof;
}

bool aggregate_dataset_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& snarkproof)
{
    snark_pp::init_public_params();

    ProverMessage statement = snarkproof[0];
    hash_chain.absorb(toString(statement));

    size_t k = statement.commVec.size()/3;

    std::vector<CommT> cm_source_A(statement.commVec.begin(), statement.commVec.begin()+k);
    std::vector<CommT> cm_source_B(statement.commVec.begin() + k, statement.commVec.begin()+ k + k);
    std::vector<CommT> cm_dest(statement.commVec.begin() + k + k, statement.commVec.end());

    // generate verifier challenge
    std::vector<FieldT> alpha = hash_chain.squeeze(k-1);
    FieldT sum = std::accumulate(alpha.begin(), alpha.end(), FieldT::zero());
    alpha.emplace_back(FieldT::one() - sum);

    // compute reduced statement
    CommT cm_x = compute_linear_combination(alpha, cm_source_A);
    CommT cm_y = compute_linear_combination(alpha, cm_source_B);
    CommT cm_z = compute_linear_combination(alpha, cm_dest);

    // get the reduced statement from the proof
    ProverMessage reduced_statement = snarkproof[1];

    // exit if computed statement is inconsistent from proof statement
    if ((cm_x != reduced_statement.commVec[0]) || (cm_y != reduced_statement.commVec[1]) || (cm_z != reduced_statement.commVec[2]))
    {
        log_message("Computed reduced statement not consistent");
        return false;
    }

    // verify the snark proof
    if (!reduced_statement.containsProof)
    {
        log_message("Malformed SNARK proof");
        return false;
    }

    auto vkfilter = read_verification_key(vkfilename);
    std::vector<FieldT> primary_input;

    if (!r1cs_adaptive_snark_verifier(
        vkfilter,
        primary_input,
        reduced_statement.commVec,
        7,
        slot_size,
        reduced_statement.proof
    )) {
        log_message("SNARK proof verification failed");
        return false;
    }   

    hash_chain.absorb(toString(reduced_statement));
    SnarkProof subproof(snarkproof.begin()+2, snarkproof.end());
    bool ret = simultaneous_permutation_snark_verifier(ROM_PERM_KEY_VK, hash_chain, slot_size, subproof);

    if (ret)
        log_message("Proof Verified Successfully");
    else
        log_message("Proof Verification Failed");

    return ret;

}

#endif