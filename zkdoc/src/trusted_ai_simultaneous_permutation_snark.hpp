#ifndef __TRUSTED_AI_SIMULTANEOUS_PERMUTATION_SNARK__
#define __TRUSTED_AI_SIMULTANEOUS_PERMUTATION_SNARK__

#include <zkdoc/src/trusted_ai_nizk.hpp>

// ******************* TOP LEVEL FUNCTIONS ************************ //

SnarkProof simultaneous_permutation_snark_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const VecVecT& left,
    const VecVecT& right,
    std::vector<FieldT>& rand_left,
    std::vector<FieldT>& rand_right
);

bool simultaneous_permutation_snark_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& proof
);

// *************************************************************** //


void parse_statement_simultaneous_perm(const ProverMessage& msg, std::vector<CommT>& cm_left, std::vector<CommT>& cm_right)
{
    size_t k = msg.commVec.size()/2;
    cm_left.clear();
    cm_right.clear();
    cm_left.insert(cm_left.end(), msg.commVec.begin(), msg.commVec.begin()+k);
    cm_right.insert(cm_right.end(), msg.commVec.begin()+k, msg.commVec.begin()+k+k);
}



SnarkProof simultaneous_permutation_snark_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const VecVecT& left,
    const VecVecT& right,
    std::vector<FieldT>& rand_left,
    std::vector<FieldT>& rand_right)
{
    snark_pp::init_public_params();

    SnarkProof snarkproof;
    assert(left.size() == right.size());
    assert(rand_left.size() == rand_right.size());
    assert(left.size() == rand_left.size());

    size_t k = left.size();
    size_t N = left[0].size();

    std::vector<CommT> cm_left(k), cm_right(k);

    // read commitment key
    std::ifstream ckfile(COMM_KEY_FILE);
    commitment_key<snark_pp> ck;
    ck.deserialize(ckfile);
    ckfile.close();

    log_message("Finished reading commitment key");

    for(size_t i=0; i < k; ++i)
    {
        cm_left[i] = compute_commitment(ck, left[i], rand_left[i]);
        cm_right[i] = compute_commitment(ck, right[i], rand_right[i]);
    }

    log_message("Finished computing commitments");

    ProverMessage statement;
    statement.commVec = cm_left;
    statement.commVec.insert(statement.commVec.end(), cm_right.begin(), cm_right.end());
    snarkproof.emplace_back(statement);
    hash_chain.absorb(toString(statement));

    log_message("Processed first prover message");

    std::vector<FieldT> coeffs = hash_chain.squeeze(k+1);
    log_message("Processed verifier challenge");

    std::vector<FieldT> beta(coeffs.begin(), coeffs.begin() + k);
    FieldT alpha = coeffs[k];

    // reduced statement
    CommT cmL(CommT::zero()), cmR(CommT::zero());
    std::vector<FieldT> X(N, FieldT::zero()), Y(N, FieldT::zero());
    FieldT rX(FieldT::zero()), rY(FieldT::zero());

    for(size_t i=0; i < k; ++i)
    {
        cmL = cmL + (beta[i] * cm_left[i]);
        cmR = cmR + (beta[i] * cm_right[i]);

        rX = rX + (beta[i] * rand_left[i]);
        rY = rY + (beta[i] * rand_right[i]);

        for(size_t j=0; j < N; ++j)
        {
            X[j] = X[j] + (beta[i] * left[i][j]);
            Y[j] = Y[j] + (beta[i] * right[i][j]);
        }
    }

    log_message("Finished computing reduced statement");
    // generate proof for the statement cmL, cmR
    ProverMessage response;
    response.commVec.emplace_back(cmL);
    response.commVec.emplace_back(cmR);

    protoboard<FieldT> pb;
    pb_variable<FieldT> random_eval_pt;
    pb_variable_array<FieldT> input, output;
    random_eval_pt.allocate(pb, "alpha");
    allocate_slot(pb, input, N, slot_size, "input");
    allocate_slot(pb, output, N, slot_size, "output");

    interactive_permutation_gadget<FieldT> perm_gadget(pb, random_eval_pt, input, output, "perm_gadget");
    perm_gadget.generate_r1cs_constraints();
    pb.set_input_sizes(1);

    pb.val(random_eval_pt) = alpha;
    input.fill_with_field_elements(pb, X);
    output.fill_with_field_elements(pb, Y);
    perm_gadget.generate_r1cs_witness();

    log_message("Reading proving key for proof generation");

    r1cs_adaptive_snark_proving_key<snark_pp> pk;
    std::ifstream pkfile(pkfilename);
    pkfile >> pk;
    pkfile.close();

    std::vector<FieldT> randomness = {rX, rY};

    log_message("Generating proof of reduced statement");
    ProofT proof = r1cs_adaptive_snark_prover<snark_pp>(
        pk,
        pb.primary_input(),
        pb.auxiliary_input(),
        randomness,
        2,
        slot_size
    );

    response.proof = proof;
    response.containsProof = true;

    snarkproof.emplace_back(response);

    log_message("Processed final prover message");

    return snarkproof;     
}


bool simultaneous_permutation_snark_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& proof
)
{
    snark_pp::init_public_params();
    
    // get the statement
    ProverMessage statement = proof[0];
    std::vector<CommT> cm_left, cm_right;
    parse_statement_simultaneous_perm(statement, cm_left, cm_right);
    hash_chain.absorb(toString(statement));

    // generate verifier challenge
    size_t k = cm_left.size();
    std::vector<FieldT> coeffs = hash_chain.squeeze(k+1);
    std::vector<FieldT> beta(coeffs.begin(), coeffs.begin()+k);
    FieldT alpha = coeffs[k];

    // compute reduced statement
    // reduced statement
    CommT cmL(CommT::zero()), cmR(CommT::zero());

    for(size_t i=0; i < k; ++i)
    {
        cmL = cmL + (beta[i] * cm_left[i]);
        cmR = cmR + (beta[i] * cm_right[i]);
    }

    log_message("Finished computing reduced statement");
    ProverMessage response = proof[1];
    if (!response.containsProof) {
        log_message("Malformed proof");
        return false;
    }

    if ((response.commVec[0] != cmL) || (response.commVec[1] != cmR))
    {
        log_message("Response mismatch");
        return false;
    }

    std::vector<FieldT> primary_input;
    primary_input.emplace_back(alpha);

    // verify the SNARK proof
    r1cs_adaptive_snark_verification_key<snark_pp> vk;
    std::ifstream vkfile(vkfilename);
    vkfile >> vk;

    bool result = r1cs_adaptive_snark_verifier(
        vk,
        primary_input,
        response.commVec,
        2,
        slot_size,
        response.proof
    );

    if (result)
    {
        log_message("Proof Verified Successfully");
    } else {
        log_message("Proof Verification Failed");
    }

    return result;

}


#endif