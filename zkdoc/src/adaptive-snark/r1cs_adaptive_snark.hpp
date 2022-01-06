#ifndef __TRUSTED_AI_R1CS_ADAPTIVE_SNARK__
#define __TRUSTED_AI_R1CS_ADAPTIVE_SNARK__

#include <zkdoc/src/adaptive-snark/trapdoor_commitment.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace libsnark;

namespace TrustedAI {

/**
 * reviewed 1
 */
template<typename ppT>
class r1cs_adaptive_snark_proving_key
{
    public:
    knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > A_query;
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query;
    knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > C_query;
    libff::G1_vector<ppT> H_query;
    libff::G1_vector<ppT> K_query;

    r1cs_ppzksnark_constraint_system<ppT> constraint_system;

    r1cs_adaptive_snark_proving_key() {};
    r1cs_adaptive_snark_proving_key<ppT>& operator=(const r1cs_adaptive_snark_proving_key<ppT> &other) = default;
    r1cs_adaptive_snark_proving_key(const r1cs_adaptive_snark_proving_key<ppT> &other) = default;
    r1cs_adaptive_snark_proving_key(r1cs_adaptive_snark_proving_key<ppT> &&other) = default;
    r1cs_adaptive_snark_proving_key(knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > &&A_query,
                               knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > &&B_query,
                               knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > &&C_query,
                               libff::G1_vector<ppT> &&H_query,
                               libff::G1_vector<ppT> &&K_query,
                               r1cs_ppzksnark_constraint_system<ppT> &&constraint_system) :
        A_query(std::move(A_query)),
        B_query(std::move(B_query)),
        C_query(std::move(C_query)),
        H_query(std::move(H_query)),
        K_query(std::move(K_query)),
        constraint_system(std::move(constraint_system))
    {};    
    

};

template<typename ppT>
std::ostream& operator<<(std::ostream& out, const r1cs_adaptive_snark_proving_key<ppT>& pk)
{
    out << pk.A_query;
    out << pk.B_query;
    out << pk.C_query;
    out << pk.H_query;
    out << pk.K_query;
    out << pk.constraint_system;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream& in, r1cs_adaptive_snark_proving_key<ppT>& pk)
{
    in >> pk.A_query;
    in >> pk.B_query;
    in >> pk.C_query;
    in >> pk.H_query;
    in >> pk.K_query;
    in >> pk.constraint_system;

    return in;
}

/**
 * reviewed
 */
template<typename ppT>
class r1cs_adaptive_snark_verification_key
{
    public:
    libff::G2<ppT> alphaA_g2;
    libff::G1<ppT> alphaB_g1;
    libff::G2<ppT> alphaC_g2;
    // the next three keys are one for each commitment block
    // including the default "witness block" (0)
    std::vector<libff::G2<ppT> > gamma_g2;
    std::vector<libff::G1<ppT> > gamma_beta_g1;
    std::vector<libff::G2<ppT> > gamma_beta_g2;
    libff::G2<ppT> rC_Z_g2;
    libff::G2<ppT> alpha_g2; // to verify commitments

    std::vector<libff::G1<ppT> > encoded_IC_query;

    r1cs_adaptive_snark_verification_key() = default;
    r1cs_adaptive_snark_verification_key(const libff::G2<ppT> &alphaA_g2,
                                    const libff::G1<ppT> &alphaB_g1,
                                    const libff::G2<ppT> &alphaC_g2,
                                    const std::vector<libff::G2<ppT>> &gamma_g2,
                                    const std::vector<libff::G1<ppT>> &gamma_beta_g1,
                                    const std::vector<libff::G2<ppT>> &gamma_beta_g2,
                                    const libff::G2<ppT> &rC_Z_g2,
                                    const libff::G2<ppT> &alpha_g2,
                                    const std::vector<libff::G1<ppT> > &eIC) :
        alphaA_g2(alphaA_g2),
        alphaB_g1(alphaB_g1),
        alphaC_g2(alphaC_g2),
        gamma_g2(gamma_g2),
        gamma_beta_g1(gamma_beta_g1),
        gamma_beta_g2(gamma_beta_g2),
        rC_Z_g2(rC_Z_g2),
        alpha_g2(alpha_g2),
        encoded_IC_query(eIC)
    {};

};

template<typename ppT>
std::ostream& operator<<(std::ostream& out, const r1cs_adaptive_snark_verification_key<ppT>& vk)
{
    out << vk.alphaA_g2 << OUTPUT_NEWLINE;
    out << vk.alphaB_g1 << OUTPUT_NEWLINE;
    out << vk.alphaC_g2 << OUTPUT_NEWLINE;
    out << vk.gamma_g2;
    out << vk.gamma_beta_g1;
    out << vk.gamma_beta_g2;
    out << vk.rC_Z_g2 << OUTPUT_NEWLINE;
    out << vk.alpha_g2 << OUTPUT_NEWLINE;
    out << vk.encoded_IC_query;

    return out;

}

template<typename ppT>
std::istream& operator>>(std::istream& in, r1cs_adaptive_snark_verification_key<ppT>& vk)
{
   in >> vk.alphaA_g2;
   libff::consume_OUTPUT_NEWLINE(in);
   in >> vk.alphaB_g1;
   libff::consume_OUTPUT_NEWLINE(in);
   in >> vk.alphaC_g2;
   libff::consume_OUTPUT_NEWLINE(in);
   in >> vk.gamma_g2;
   in >> vk.gamma_beta_g1;
   in >> vk.gamma_beta_g2;
   in >> vk.rC_Z_g2;
   libff::consume_OUTPUT_NEWLINE(in);
   in >> vk.alpha_g2;
   libff::consume_OUTPUT_NEWLINE(in);
   in >> vk.encoded_IC_query;

   return in; 
}



/**
 * reviewed
 */
template<typename ppT>
class r1cs_adaptive_snark_keypair {
public:
    r1cs_adaptive_snark_proving_key<ppT> pk;
    r1cs_adaptive_snark_verification_key<ppT> vk;

    r1cs_adaptive_snark_keypair() = default;
    r1cs_adaptive_snark_keypair(const r1cs_adaptive_snark_keypair<ppT> &other) = default;
    r1cs_adaptive_snark_keypair(r1cs_adaptive_snark_proving_key<ppT> &&pk,
                           r1cs_adaptive_snark_verification_key<ppT> &&vk) :
        pk(std::move(pk)),
        vk(std::move(vk))
    {};

    r1cs_adaptive_snark_keypair(r1cs_adaptive_snark_keypair<ppT> &&other) = default;
};


/**
 * reviewed
 */
template<typename ppT>
r1cs_adaptive_snark_keypair<ppT>  r1cs_adaptive_snark_generator(
    const r1cs_ppzksnark_constraint_system<ppT> &cs,
    const commitment_key<ppT>& ck,
    const size_t num_comm_slots,
    const size_t size_comm_slot)
{
    size_t p = cs.num_inputs();
    size_t K = num_comm_slots;
    size_t N = size_comm_slot;

    /* draw random element at which the QAP is evaluated */
    const  libff::Fr<ppT> t = libff::Fr<ppT>::random_element();

    qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_qap_instance_map_with_evaluation(cs, t);
    r1cs_ppzksnark_constraint_system<ppT> cs_copy(cs);

    libff::print_indent(); printf("* QAP number of variables: %zu\n", qap_inst.num_variables());
    libff::print_indent(); printf("* QAP pre degree: %zu\n", cs.constraints.size());
    libff::print_indent(); printf("* QAP degree: %zu\n", qap_inst.degree());
    libff::print_indent(); printf("* QAP number of input variables: %zu\n", qap_inst.num_inputs());

    libff::enter_block("Compute query densities");
    size_t non_zero_At = 0, non_zero_Bt = 0, non_zero_Ct = 0, non_zero_Ht = 0;
    for (size_t i = 0; i < qap_inst.num_variables()+1; ++i)
    {
        if (!qap_inst.At[i].is_zero())
        {
            ++non_zero_At;
        }
        if (!qap_inst.Bt[i].is_zero())
        {
            ++non_zero_Bt;
        }
        if (!qap_inst.Ct[i].is_zero())
        {
            ++non_zero_Ct;
        }
    }
    for (size_t i = 0; i < qap_inst.degree()+1; ++i)
    {
        if (!qap_inst.Ht[i].is_zero())
        {
            ++non_zero_Ht;
        }
    }
    libff::leave_block("Compute query densities");

    libff::Fr_vector<ppT> At = std::move(qap_inst.At); // qap_inst.At is now in unspecified state, but we do not use it later
    libff::Fr_vector<ppT> Bt = std::move(qap_inst.Bt); // qap_inst.Bt is now in unspecified state, but we do not use it later
    libff::Fr_vector<ppT> Ct = std::move(qap_inst.Ct); // qap_inst.Ct is now in unspecified state, but we do not use it later
    libff::Fr_vector<ppT> Ht = std::move(qap_inst.Ht); // qap_inst.Ht is now in unspecified state, but we do not use it later

    /* append Zt to At,Bt,Ct with */
    At.emplace_back(qap_inst.Zt);
    Bt.emplace_back(qap_inst.Zt);
    Ct.emplace_back(qap_inst.Zt);

    const  libff::Fr<ppT> alphaA = libff::Fr<ppT>::random_element(),
        alphaB = libff::Fr<ppT>::random_element(),
        alphaC = libff::Fr<ppT>::random_element(),
        rA = libff::Fr<ppT>::random_element(),
        rB = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT>  rC = rA * rB;

    libff::Fr_vector<ppT> beta, gamma;
    for(size_t i=0; i < num_comm_slots + 1; ++i)
    {
        beta.emplace_back(libff::Fr<ppT>::random_element());
        gamma.emplace_back(libff::Fr<ppT>::random_element());
    }


    libff::Fr_vector<ppT> Kt;
    for (size_t i = 0; i < qap_inst.num_variables()+1; ++i)
    {
        size_t slot_index = 0;
        
        if (i <= p || i > p+K*N)
        {
            slot_index = 0;
        } else {
            slot_index = 1 + (i - p - 1)/N;
        }

        // will need to adjust K_Query terms corresponding to non-zero slot index
        // with suitable multiples of commitment key entries later.
        Kt.emplace_back( beta[slot_index] * (rA * At[i] + rB * Bt[i] + rC * Ct[i]) );
    }

    for(size_t i=0; i < K+1; ++i)
    {
        Kt.emplace_back(beta[i] * rA * qap_inst.Zt);
        Kt.emplace_back(beta[i] * rB * qap_inst.Zt);
        Kt.emplace_back(beta[i] * rC * qap_inst.Zt);
        Kt.emplace_back(beta[i]);
    }

       /* zero out prefix of At and stick it into IC coefficients */
    libff::Fr_vector<ppT> IC_coefficients;
    IC_coefficients.reserve(qap_inst.num_inputs() + 1);
    for (size_t i = 0; i < qap_inst.num_inputs() + 1; ++i)
    {
        IC_coefficients.emplace_back(At[i]);
        assert(!IC_coefficients[i].is_zero());
        At[i] = libff::Fr<ppT>::zero();
    }

    const size_t g1_exp_count = 2*(non_zero_At - qap_inst.num_inputs() + non_zero_Ct) + non_zero_Bt + non_zero_Ht + Kt.size();
    const size_t g2_exp_count = non_zero_Bt;

    size_t g1_window = libff::get_exp_window_size<libff::G1<ppT> >(g1_exp_count);
    size_t g2_window = libff::get_exp_window_size<libff::G2<ppT> >(g2_exp_count);
    libff::print_indent(); printf("* G1 window: %zu\n", g1_window);
    libff::print_indent(); printf("* G2 window: %zu\n", g2_window);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Generating G1 multiexp table");
    libff::window_table<libff::G1<ppT> > g1_table = get_window_table(libff::Fr<ppT>::size_in_bits(), g1_window, libff::G1<ppT>::one());
    libff::leave_block("Generating G1 multiexp table");

    libff::enter_block("Generating G2 multiexp table");
    libff::window_table<libff::G2<ppT> > g2_table = get_window_table(libff::Fr<ppT>::size_in_bits(), g2_window, libff::G2<ppT>::one());
    libff::leave_block("Generating G2 multiexp table");

    libff::enter_block("Generate R1CS proving key");

    libff::enter_block("Generate knowledge commitments");
    libff::enter_block("Compute the A-query", false);
    knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > A_query = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rA, rA*alphaA, At, chunks);
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g2_window, g1_window, g2_table, g1_table, rB, rB*alphaB, Bt, chunks);
    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the C-query", false);
    knowledge_commitment_vector<libff::G1<ppT>, libff::G1<ppT> > C_query = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rC, rC*alphaC, Ct, chunks);
    libff::leave_block("Compute the C-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_query = batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute the K-query", false);
    libff::G1_vector<ppT> K_query = batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(K_query);
#endif
    libff::leave_block("Compute the K-query", false);

    // Need to adjust the K-Query terms with beta multiples of commitment key
    libff::enter_block("Adjust K-Query", false);

    for (size_t i = p+1; i < p+K*N+1; ++i)
    {
        size_t slot_index = 1 + (i - p - 1)/N;
        size_t within_slot_index = i - N*(slot_index - 1) - p;
        K_query[i] = K_query[i] + beta[slot_index] * ck.key_[within_slot_index].g;
        //@todo -- commitment randomness also needs to be incorporated here.
    }

    libff::leave_block("Adjust K-Query", false);

    // Generate Verification Key
    libff::G2<ppT> alphaA_g2 = alphaA * libff::G2<ppT>::one();
    libff::G1<ppT> alphaB_g1 = alphaB * libff::G1<ppT>::one();
    libff::G2<ppT> alphaC_g2 = alphaC * libff::G2<ppT>::one();
    libff::G2<ppT> rC_Z_g2 = (rC * qap_inst.Zt) * libff::G2<ppT>::one();
    std::vector<libff::G2<ppT>> gamma_g2;
    std::vector<libff::G1<ppT>> gamma_beta_g1;
    std::vector<libff::G2<ppT>> gamma_beta_g2;

    for(size_t i=0; i < K+1; ++i)
    {
        gamma_g2.emplace_back(gamma[i] * libff::G2<ppT>::one());
        gamma_beta_g1.emplace_back((gamma[i] * beta[i]) * libff::G1<ppT>::one());
        gamma_beta_g2.emplace_back((gamma[i] * beta[i]) * libff::G2<ppT>::one());
    }

    libff::enter_block("Encode IC query for R1CS verification key");
    //libff::G1<ppT> encoded_IC_base = (rA * IC_coefficients[0]) * libff::G1<ppT>::one();
    libff::Fr_vector<ppT> multiplied_IC_coefficients;
    //multiplied_IC_coefficients.reserve(qap_inst.num_inputs());
    multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[0]);
    for (size_t i = 1; i < qap_inst.num_inputs() + 1; ++i)
    {
        multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[i]);
    }
    libff::G1_vector<ppT> encoded_IC_values = batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g1_table, multiplied_IC_coefficients);

    libff::leave_block("Encode IC query for R1CS verification key");


    //accumulation_vector<libff::G1<ppT> > encoded_IC_query(std::move(encoded_IC_base), std::move(encoded_IC_values));
    r1cs_adaptive_snark_verification_key<ppT> vk = r1cs_adaptive_snark_verification_key<ppT>(alphaA_g2,
                                                                                   alphaB_g1,
                                                                                   alphaC_g2,
                                                                                   gamma_g2,
                                                                                   gamma_beta_g1,
                                                                                   gamma_beta_g2,
                                                                                   rC_Z_g2,
                                                                                   ck.key_[0].h,
                                                                                   encoded_IC_values);

    r1cs_adaptive_snark_proving_key<ppT> pk = r1cs_adaptive_snark_proving_key<ppT>(std::move(A_query),
                                                                         std::move(B_query),
                                                                         std::move(C_query),
                                                                         std::move(H_query),
                                                                         std::move(K_query),
                                                                         std::move(cs_copy));


    return r1cs_adaptive_snark_keypair<ppT>(std::move(pk), std::move(vk));

}

/**
 * reviewed
 */
template<typename ppT>
class r1cs_adaptive_snark_proof
{
    public:
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > g_A;
    std::vector<knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > > g_B;
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > g_C;
    libff::G1<ppT> g_H;
    std::vector<libff::G1<ppT>> g_K;


    r1cs_adaptive_snark_proof()
    {
        g_H = libff::G1<ppT>::zero();
    };

    r1cs_adaptive_snark_proof(
               std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > &&g_A,
               std::vector<knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > > &&g_B,
               std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > &&g_C,
               libff::G1<ppT> &&g_H,
               std::vector<libff::G1<ppT> > &&g_K) :
        g_A(std::move(g_A)),
        g_B(std::move(g_B)),
        g_C(std::move(g_C)),
        g_H(std::move(g_H)),
        g_K(std::move(g_K))
    {};    

};

template<typename ppT>
std::ostream& operator<<(std::ostream& out, const r1cs_adaptive_snark_proof<ppT>& proof)
{
    out << proof.g_A;
    out << proof.g_B;
    out << proof.g_C;
    out << proof.g_H << OUTPUT_NEWLINE;
    out << proof.g_K;

    return out;

}

template<typename ppT>
std::istream& operator>>(std::istream& in, r1cs_adaptive_snark_proof<ppT>& proof)
{
    in >> proof.g_A;
    in >> proof.g_B;
    in >> proof.g_C;
    in >> proof.g_H;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.g_K;

    return in;
}



/**
 * reviewed
 */
template<typename ppT>
r1cs_adaptive_snark_proof<ppT> r1cs_adaptive_snark_prover(
    const r1cs_adaptive_snark_proving_key<ppT> &pk,
    const std::vector<libff::Fr<ppT>>& primary_input,
    const std::vector<libff::Fr<ppT>>& auxiliary_input,
    const std::vector<libff::Fr<ppT>>& commitment_randomness,
    // const std::vector<knowledge_commitment<libff::G1<ppT>, libff::G2<ppT>>>& commited_input,
    const size_t num_slots,
    const size_t slot_size
)
{
    //assert(commited_input.size() == num_slots);
    
    // sample the randomization coefficients
    std::vector<libff::Fr<ppT>> d1, d2, d3;
    libff::Fr<ppT> D1 = libff::Fr<ppT>::zero(), D2 = libff::Fr<ppT>::zero(), D3 = libff::Fr<ppT>::zero();

    size_t p = primary_input.size();
    size_t K = num_slots;
    size_t N = slot_size;

    for(size_t i=0; i < K+1; ++i)
    {
        d1.emplace_back(libff::Fr<ppT>::random_element());
        d2.emplace_back(libff::Fr<ppT>::random_element());
        d3.emplace_back(libff::Fr<ppT>::random_element());
    }

    for(size_t i=0; i < K+1; ++i)
    {
        D1 = D1 + d1[i];
        D2 = D2 + d2[i];
        D3 = D3 + d3[i];
    }

    libff::enter_block("Compute H polynomial");
    const qap_witness<libff::Fr<ppT>> qap_wit = r1cs_to_qap_witness_map(pk.constraint_system, primary_input, auxiliary_input, D1, D2, D3);
    libff::leave_block("Compute the polynomial H");

    // compute proof elements for each slot. Slot 0 splits up into public inputs and the non-committed witness
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>> g_A(K+1, knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>::zero());    
    std::vector<knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>> g_B(K+1, knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>::zero());    
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>> g_C(K+1, knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>::zero());
    libff::G1<ppT> g_H = libff::G1<ppT>::zero();
    std::vector<libff::G1<ppT>> g_K(K+1, libff::G1<ppT>::zero());


    g_A[0] = pk.A_query[0];
    g_B[0] = pk.B_query[0];
    g_C[0] = pk.C_query[0];

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    // add the public input parts
    g_A[0] = g_A[0] + d1[0] * pk.A_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.A_query,
        1, 1+qap_wit.num_inputs(),
        qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_inputs(),
        chunks);

    g_B[0] = g_B[0] + d2[0] * pk.B_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.B_query,
        1, 1+qap_wit.num_inputs(),
        qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_inputs(),
        chunks);

    g_C[0] = g_C[0] + d3[0] * pk.C_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.C_query,
        1, 1+qap_wit.num_inputs(),
        qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_inputs(),
        chunks);


    g_K[0] = g_K[0] +  pk.K_query[0] + d1[0]*pk.K_query[qap_wit.num_variables()+1] + d2[0] * pk.K_query[qap_wit.num_variables()+2] 
                    + d3[0]* pk.K_query[qap_wit.num_variables()+3];
    
    g_K[0] = g_K[0] + libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                     libff::Fr<ppT>,
                                                     libff::multi_exp_method_bos_coster>(
        pk.K_query.begin()+1, pk.K_query.begin()+1+qap_wit.num_inputs(),
        qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_inputs(),
        chunks);
    

    // add the uncommited witness part
    g_A[0] = g_A[0] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.A_query,
        p+1+K*N, qap_wit.num_variables()+1,
        qap_wit.coefficients_for_ABCs.begin() + (p+K*N), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_variables(),
        chunks);

    g_B[0] = g_B[0] + kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.B_query,
        p+1+K*N, qap_wit.num_variables()+1,
        qap_wit.coefficients_for_ABCs.begin() + (p+K*N), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_variables(),
        chunks);

    g_C[0] = g_C[0] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G1<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        pk.C_query,
        p+1+K*N, qap_wit.num_variables()+1,
        qap_wit.coefficients_for_ABCs.begin() + (p+K*N), qap_wit.coefficients_for_ABCs.begin()+qap_wit.num_variables(),
        chunks);

    g_K[0] = g_K[0] + libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                     libff::Fr<ppT>,
                                                     libff::multi_exp_method_bos_coster>(
        pk.K_query.begin()+(p+1+K*N),
        pk.K_query.begin() + qap_wit.num_variables() + 1,
        qap_wit.coefficients_for_ABCs.begin() + p + K*N,
        qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(),
        chunks);
        

    // now compute proof elements for remaining slots
    for(size_t slot = 1; slot < K+1; ++slot)
    {
        g_A[slot] = g_A[slot] + d1[slot] * pk.A_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                           libff::G1<ppT>,
                                                           libff::Fr<ppT>,
                                                           libff::multi_exp_method_bos_coster>(
                              pk.A_query,
                              p + 1 + (slot - 1) * N,
                              p + 1 + slot * N,
                              qap_wit.coefficients_for_ABCs.begin() + (p + (slot - 1) * N),
                              qap_wit.coefficients_for_ABCs.begin() + (p + slot * N),
                              chunks);

        g_B[slot] = g_B[slot] + d2[slot] * pk.B_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                           libff::G1<ppT>,
                                                           libff::Fr<ppT>,
                                                           libff::multi_exp_method_bos_coster>(
                              pk.B_query,
                              p + 1 + (slot - 1) * N,
                              p + 1 + slot * N,
                              qap_wit.coefficients_for_ABCs.begin() + (p + (slot - 1) * N),
                              qap_wit.coefficients_for_ABCs.begin() + (p + slot * N),
                              chunks);

        g_C[slot] = g_C[slot] + d3[slot] * pk.C_query[qap_wit.num_variables()+1] + kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                           libff::G1<ppT>,
                                                           libff::Fr<ppT>,
                                                           libff::multi_exp_method_bos_coster>(
                              pk.C_query,
                              p + 1 + (slot - 1) * N,
                              p + 1 + slot * N,
                              qap_wit.coefficients_for_ABCs.begin() + (p + (slot - 1) * N),
                              qap_wit.coefficients_for_ABCs.begin() + (p + slot * N),
                              chunks);

        g_K[slot] = g_K[slot] +  d1[slot]*pk.K_query[qap_wit.num_variables()+1+4*slot] + d2[slot] * pk.K_query[qap_wit.num_variables()+2+4*slot] 
                    + d3[slot]* pk.K_query[qap_wit.num_variables()+3+4*slot] + commitment_randomness[slot-1] * pk.K_query[qap_wit.num_variables()+4+4*slot];

        g_K[slot] = g_K[slot] + libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                     libff::Fr<ppT>,
                                                     libff::multi_exp_method_bos_coster>(
            pk.K_query.begin() + (p+1+(slot-1)*N),
            pk.K_query.begin() + (p+1+slot*N),
            qap_wit.coefficients_for_ABCs.begin() + (p + (slot-1)*N),
            qap_wit.coefficients_for_ABCs.begin() + (p+slot*N),
            chunks); 
        

        
    }

    g_H = g_H + libff::multi_exp<libff::G1<ppT>,
                                 libff::Fr<ppT>,
                                 libff::multi_exp_method_BDLO12>(
        pk.H_query.begin(), pk.H_query.begin()+qap_wit.degree()+1,
        qap_wit.coefficients_for_H.begin(), qap_wit.coefficients_for_H.begin()+qap_wit.degree()+1,
        chunks);

    return r1cs_adaptive_snark_proof<ppT>(
        std::move(g_A),
        std::move(g_B),
        std::move(g_C),
        std::move(g_H),
        std::move(g_K)
    );


}

template<typename ppT>
bool r1cs_adaptive_snark_verifier(
    const r1cs_adaptive_snark_verification_key<ppT>& vk,
    const std::vector<libff::Fr<ppT>>& primary_input,
    const std::vector<knowledge_commitment<libff::G1<ppT>, libff::G2<ppT> > >& committed_inputs,
    size_t num_slots,
    size_t slot_size,
    const r1cs_adaptive_snark_proof<ppT>& proof)
{
    assert(committed_inputs.size() == num_slots);
    assert(primary_input.size() + 1 == vk.encoded_IC_query.size());

    // accumulate public inputs
    libff::G1<ppT> acc = vk.encoded_IC_query[0] + libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                     libff::Fr<ppT>,
                                                     libff::multi_exp_method_bos_coster>(
        vk.encoded_IC_query.begin()+1, vk.encoded_IC_query.begin()+1+primary_input.size(),
        primary_input.begin(), primary_input.end(),
        1);
    // compute g_A_pub from public input part
    // For each slot check:
    // Check: e(proof.g_A, alphaA) = e(proof.alphaA_g_A, 1)
    // Check: e(proof.g_B, alphaB) = e(proof.alphaB_g_B, 1)
    // Check: e(proof.g_C, alphaC) = e(proof.alphaC_g_C, 1)
    // Check: e(<Comm>_i + <A_i> + <B_i> + <C_i>, gamma_i) = e(K_i, gamma_i.beta_i)
    // Verification Key Components:
    /*
    libff::G2<ppT> alphaA_g2;
    libff::G1<ppT> alphaB_g1;
    libff::G2<ppT> alphaC_g2;
    // the next three keys are one for each commitment block
    // including the default "witness block" (0)
    std::vector<libff::G2<ppT> > gamma_g2;
    std::vector<libff::G1<ppT> > gamma_beta_g1;
    std::vector<libff::G2<ppT> > gamma_beta_g2;
    libff::G2<ppT> rC_Z_g2;
    libff::G2<ppT> alpha_g2; // to verify commitments
    std::vector<libff::G1<ppT> > encoded_IC_query;
    */

    // Proof Components:
    /*
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > g_A;
    std::vector<knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > > g_B;
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > > g_C;
    libff::G1<ppT> g_H;
    std::vector<libff::G1<ppT>> g_K;
    */

    bool result = true;
    for(size_t i=0; i < num_slots; ++i)
    {
        if (ppT::reduced_pairing(proof.g_A[i].g, vk.alphaA_g2) != ppT::reduced_pairing(proof.g_A[i].h, libff::G2<ppT>::one()))
        {
            std::cout << "Knowledge Commitment A for slot " << i << " failed consistency check" << std::endl;
            return false;
        }
    
        if (ppT::reduced_pairing(vk.alphaB_g1, proof.g_B[i].g) != ppT::reduced_pairing(proof.g_B[i].h, libff::G2<ppT>::one()))
        {
            std::cout << "Knowledge Commitment B for slot " << i << " failed consistency check" << std::endl;
            return false;
        }

        if (ppT::reduced_pairing(proof.g_C[i].g, vk.alphaC_g2) != ppT::reduced_pairing(proof.g_C[i].h, libff::G2<ppT>::one()))
        {
            std::cout << "Knowledge Commitment C for slot " << i << " failed consistency check" << std::endl;
            return false;
        }

    }

    // check same coefficients used
    
    for(size_t i=0; i < num_slots; ++i)
    {
        libff::G1<ppT> aterm = (i==0)?acc:libff::G1<ppT>::zero();
        libff::G1<ppT> cterm = (i==0)?libff::G1<ppT>::zero():committed_inputs[i-1].g;
        if (ppT::reduced_pairing(proof.g_K[i], vk.gamma_g2[i]) != 
            (ppT::reduced_pairing(proof.g_A[i].g + aterm + proof.g_C[i].g + cterm, vk.gamma_beta_g2[i]) *
                ppT::reduced_pairing(vk.gamma_beta_g1[i], proof.g_B[i].g))) 
        {
            std::cout << "Same coefficient check failed for slot " << i << std::endl;
            return false;
        }
    }
    

    // divisibility check
    libff::G1<ppT> A = libff::G1<ppT>::zero();
    libff::G2<ppT> B = libff::G2<ppT>::zero();
    libff::G1<ppT> C = libff::G1<ppT>::zero();

    for(size_t i=0; i < num_slots + 1; ++i)
    {
        A = A + proof.g_A[i].g;
        B = B + proof.g_B[i].g;
        C = C + proof.g_C[i].g;
    }

    if (ppT::reduced_pairing(A+acc, B) != (ppT::reduced_pairing(proof.g_H, vk.rC_Z_g2) * ppT::reduced_pairing(C, libff::G2<ppT>::one())))
    {
        std::cout << "QAP Divisibility Check failed" << std::endl;
        return false;
    }

    return result;

}

} // namespace TrustedAI

#endif




