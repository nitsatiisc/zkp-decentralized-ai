#ifndef __TRUSTED_AI_ROM_ACCESS__
#define __TRUSTED_AI_ROM_ACCESS__
#include <zkdoc/src/trusted_ai_nizk.hpp>
#include <zkdoc/src/trusted_ai_simultaneous_permutation_snark.hpp>

// ************************************************************************* //
//                          TOP LEVEL API                                    //
typedef struct {
    VecVecT mem_list;
    std::vector<FieldT> rand_mem_list;
} MemInfoT;

typedef struct {
    std::vector<FieldT> read_locations;
    FieldT rand_read_locations;
} AccessInfoT;

typedef struct {
    VecVecT values_list;
    std::vector<FieldT> rand_values_list;
} ValueInfoT;


SnarkProof multiplexed_rom_access_prover(
    const std::string& pkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const MemInfoT& mem_info,
    const AccessInfoT& access_info,
    const ValueInfoT& val_info
)
{
    // init
    snark_pp::init_public_params();

    auto mem_list = mem_info.mem_list;
    auto rand_mem_list = mem_info.rand_mem_list;
    auto read_locations = access_info.read_locations;
    auto rand_read_locations = access_info.rand_read_locations;
    auto values_list = val_info.values_list;
    auto rand_values_list = val_info.rand_values_list;


    size_t k = mem_list.size();
    assert(rand_mem_list.size() == k); 
    assert(values_list.size() == k);
    assert(rand_values_list.size() == k);
    
    // compute commitments for mem_list, read_locations, values_list
    commitment_key<snark_pp> ck;
    std::ifstream ckfile(COMM_KEY_FILE);
    ck.deserialize(ckfile);
    
    auto cm_mem = compute_comm_list(ck, mem_list, rand_mem_list);
    auto cm_val = compute_comm_list(ck, values_list, rand_values_list);
    auto cm_loc = compute_commitment(ck, read_locations, rand_read_locations);

    SnarkProof snarkproof;
    ProverMessage statement;
    statement.commVec = cm_mem;
    statement.commVec.emplace_back(cm_loc);
    statement.commVec.insert(statement.commVec.end(), cm_val.begin(), cm_val.end());
    snarkproof.emplace_back(statement);
    hash_chain.absorb(toString(statement));

    std::vector<FieldT> coeffs = hash_chain.squeeze(k);
    auto cm_L = compute_linear_combination(coeffs, cm_mem);
    auto cm_V = compute_linear_combination(coeffs, cm_val);
    auto cm_U = cm_loc;
    auto r_L = compute_linear_combination(coeffs, rand_mem_list);
    auto r_V = compute_linear_combination(coeffs, rand_values_list);
    auto r_U = rand_read_locations;

    auto L = compute_linear_combination(coeffs, mem_list);
    auto V = compute_linear_combination(coeffs, values_list);
    auto U = read_locations;

    protoboard<FieldT> pb; 

    pb_variable_array<FieldT> pb_L, pb_U, pb_V;
    pb_variable_array<FieldT> pb_uL, pb_vL, pb_uR, pb_vR;

    size_t n = L.size();
    size_t m = U.size();

    allocate_slot(pb, pb_L, n, slot_size, "pb_L");
    allocate_slot(pb, pb_U, m, slot_size, "pb_U");
    allocate_slot(pb, pb_V, m, slot_size, "pb_V");
    allocate_slot(pb, pb_uL, m+n, slot_size, "pb_uL");
    allocate_slot(pb, pb_vL, m+n, slot_size, "pb_vL");
    allocate_slot(pb, pb_uR, m+n, slot_size, "pb_uR");
    allocate_slot(pb, pb_vR, m+n, slot_size, "pb_vR");

    pb_L.fill_with_field_elements(pb, L);
    pb_U.fill_with_field_elements(pb, U);
    pb_V.fill_with_field_elements(pb, V);

    interactive_lookup_arithmetic<FieldT> lookup_arith_gadget(pb, pb_L, pb_U, pb_V, pb_uL, pb_vL, pb_uR, pb_vR, "lookup_arith_gadget");
    lookup_arith_gadget.generate_r1cs_constraints();
    lookup_arith_gadget.generate_r1cs_witness();

    std::vector<FieldT> uL = pb_uL.get_vals(pb);
    std::vector<FieldT> vL = pb_vL.get_vals(pb);
    std::vector<FieldT> uR = pb_uR.get_vals(pb);
    std::vector<FieldT> vR = pb_vR.get_vals(pb);

    // additional commitment randomness for output vectors
    auto ruL = FieldT::random_element();
    auto rvL = FieldT::random_element();
    auto ruR = FieldT::random_element();
    auto rvR = FieldT::random_element();

    // compute intermediate commitments
    auto cm_uL = compute_commitment(ck, uL, ruL);
    auto cm_vL = compute_commitment(ck, vL, rvL);
    auto cm_uR = compute_commitment(ck, uR, ruR);
    auto cm_vR = compute_commitment(ck, vR, rvR);

    std::vector<FieldT> rand_vec = {r_L, r_U, r_V, ruL, rvL, ruR, rvR};
    std::vector<CommT> cm_vec = {cm_L, cm_U, cm_V, cm_uL, cm_vL, cm_uR, cm_vR};

    ProverMessage reduced_statement;
    reduced_statement.commVec = cm_vec;

    r1cs_adaptive_snark_proving_key<snark_pp> rom_pk;
    std::ifstream rompkfile(ROM_KEY_PK);
    rompkfile >> rom_pk;
    rompkfile.close();

    auto proof = r1cs_adaptive_snark_prover(
        rom_pk,
        pb.primary_input(),
        pb.auxiliary_input(),
        rand_vec,
        7,
        slot_size);

    reduced_statement.proof = proof;
    reduced_statement.containsProof = true;
    snarkproof.emplace_back(reduced_statement);
    hash_chain.absorb(toString(reduced_statement));

    // setup parameters for sub-protocol
    VecVecT left = {uL, vL};
    VecVecT right = {uR, vR};
    std::vector<FieldT> rand_left = {ruL, rvL};
    std::vector<FieldT> rand_right = {ruR, rvR};

    SnarkProof subproof = simultaneous_permutation_snark_prover(ROM_PERM_KEY_PK, hash_chain, slot_size, left, right, rand_left, rand_right);
    snarkproof.insert(snarkproof.end(), subproof.begin(), subproof.end());

    return snarkproof;    
}

bool multiplexed_rom_access_verifier(
    const std::string& vkfilename,
    HashChainT& hash_chain,
    size_t slot_size,
    const SnarkProof& proof
)
{
    snark_pp::init_public_params();

    ProverMessage statement = proof[0];
    auto comm_vec = statement.commVec;

    size_t k = (comm_vec.size() - 1)/2;
    hash_chain.absorb(toString(statement));

    std::vector<CommT> cm_mem(comm_vec.begin(), comm_vec.begin()+k);
    auto cm_loc = comm_vec[k];
    std::vector<CommT> cm_val(comm_vec.begin() + k + 1, comm_vec.end());

    std::vector<FieldT> coeffs = hash_chain.squeeze(k);

    ProverMessage reduced_statement = proof[1];
    auto computed_cm_L = compute_linear_combination(coeffs, cm_mem);
    auto computed_cm_V = compute_linear_combination(coeffs, cm_val);
    auto computed_cm_U = cm_loc;

    auto rc_comm_vec = reduced_statement.commVec;
    if ((computed_cm_L != rc_comm_vec[0]) || (computed_cm_U != rc_comm_vec[1]) || (computed_cm_V != rc_comm_vec[2]))
    {
        log_message("Reduced Statement Mismatch");
        return false;
    }

    if (!reduced_statement.containsProof)
    {
        log_message("Malformed Proof");
        return false;
    }   

    // verify proof 
    std::ifstream vkfile(vkfilename);
    r1cs_adaptive_snark_verification_key<snark_pp> rom_vk;
    vkfile >> rom_vk;

    std::vector<FieldT> primary_input;

    if (!r1cs_adaptive_snark_verifier(
        rom_vk,
        primary_input,
        rc_comm_vec,
        7,
        slot_size,
        reduced_statement.proof
    )) {
        log_message("ROM Proof Verification Failed");
        return false;
    }

    hash_chain.absorb(toString(reduced_statement));
    SnarkProof subproof(proof.begin()+2, proof.end());

    return simultaneous_permutation_snark_verifier(
        ROM_PERM_KEY_VK,
        hash_chain,
        slot_size,
        subproof
    );




}



















#endif