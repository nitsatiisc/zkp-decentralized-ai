
// include libsnark headers
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>

// include dependent headers
#include <zkdoc/src/trusted_ai_interactive_gadgets.hpp>
#include <zkdoc/src/adaptive-snark/trapdoor_commitment.hpp>
#include <zkdoc/src/adaptive-snark/r1cs_adaptive_snark.hpp>
#include <zkdoc/src/trusted_ai_cp_gadgets.hpp>

#include <iostream>
#include <cassert>
#include <fstream>
#include <numeric>
#include <algorithm>
#include <random>
#include <tuple>


using namespace TrustedAI;
using namespace libsnark;

typedef libff::alt_bn128_pp snark_pp;
typedef libff::Fr<snark_pp> FieldT;

template <typename FieldT>
void print_protoboard_info(protoboard<FieldT> &pb)
{
    std::cout << "Protoboard Satisfied: [ " << pb.is_satisfied() << " ]" << std::endl;
    std::cout << "Protoboard Constraints: [ " << pb.num_constraints() << " ]" << std::endl;
    std::cout << "Protoboard Variables: [ " << pb.num_variables() << " ]" << std::endl;
}

unsigned int get_random_value(size_t n)
{
    std::random_device rd;  // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> distrib(0, n-1);
    return distrib(gen);
}

struct proto_stats {
    long long generator_time;
    long long prover_time;
    long long verifier_time;
    uint64_t num_constraints;
    bool status;
};


struct filter_example_type {
    unsigned int size;
    std::vector<size_t> source;
    std::vector<size_t> f;
    std::vector<size_t> target;
};

filter_example_type
generate_filter_example(size_t n)
{
    filter_example_type example;
    example.size = get_random_value(n);
    for(size_t i=0; i < example.size; ++i) {
        example.source.emplace_back(get_random_value(1000));
        example.f.emplace_back(get_random_value(2));
    }

    for(size_t i=0; i < example.size; ++i)
    {
        if (example.f[i] == 1)
            example.target.emplace_back(example.source[i]);
    }

    return example;
}

struct merge_transcript {
    // result of join
    std::vector<size_t> p, q, r;

    // transcript
    std::vector<size_t> tr_X;
    std::vector<size_t> tr_Y;
    std::vector<size_t> tr_Z;
    std::vector<size_t> tr_W;
    std::vector<size_t> tr_I;
    std::vector<size_t> tr_J;
    std::vector<size_t> tr_O;
    std::vector<size_t> tr_S;

};

merge_transcript
generate_merge_transcript(
    std::vector<size_t>& x,
    std::vector<size_t>& y,
    std::vector<size_t>& z,
    std::vector<size_t>& w)
{
    // We ensure y and z are sorted
    size_t sizey = y[0];
    size_t sizez = z[0];
    std::sort(y.begin() + 1, y.begin() + 1 + sizey);
    std::sort(z.begin() + 1, z.begin() + 1 + sizez);


    merge_transcript tr;
    size_t n = x.size() - 1;

    tr.tr_X.resize(2*n);
    tr.tr_Y.resize(2*n);
    tr.tr_Z.resize(2*n);
    tr.tr_W.resize(2*n);
    tr.tr_I.resize(2*n);
    tr.tr_J.resize(2*n);
    tr.tr_O.resize(2*n);
    tr.tr_S.resize(2*n);

    size_t I=1;
    size_t J=1;

    tr.tr_O[0] = 0;

    for(size_t i=0; i < 2*n; ++i)
    {
        tr.tr_X[i] = x[I];
        tr.tr_Y[i] = y[I];
        tr.tr_Z[i] = z[J];
        tr.tr_W[i] = w[J];

        tr.tr_I[i] = I;
        tr.tr_J[i] = J;

        if (i > 0) {
            tr.tr_O[i] = (tr.tr_I[i-1] == sizey) && (tr.tr_J[i-1] == sizez);
        }

        size_t incr_i = 0;
        size_t incr_j = 0;

        if ((y[I] <= z[J]) && (I < sizey))
            incr_i = 1;
        
        if ((y[I] >= z[J]) && (J < sizez))
            incr_j = 1;

        if ((y[I] == z[J]) && (tr.tr_O[i] == 0))
            tr.tr_S[i] = 1;
        else
            tr.tr_S[i] = 0;

        I = I + incr_i;
        J = J + incr_j;

    }

    for(size_t i=0; i < 2*n; ++i)
    {
        if (tr.tr_S[i] == 1) {
            tr.p.emplace_back(tr.tr_X[i]);
            tr.q.emplace_back(tr.tr_Y[i]);
            tr.r.emplace_back(tr.tr_W[i]);
        }
    }

    return tr;

}

template<typename FieldT>
std::vector<std::vector<FieldT> > generate_decision_tree(size_t n)
{
    std::vector<std::vector<uint64_t> > tree_matrix = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
        {1, 2, 3, 4, 0, 0, 5, 0, 0, 0, 0},
        {100, 40, 50, 20, 0, 50, 20, 0, 0, 0, 0},
        {1, 3, 5, 7, 4, 5, 9, 7, 8, 9, 10},
        {2, 4, 6, 8, 4, 5, 10, 7, 8, 9, 10},
        {2, 2, 2, 2, 0, 1, 2, 0, 1, 1, 0}};

    for (size_t i = 0; i < tree_matrix.size(); ++i)
    {
        tree_matrix[i].resize(n, 0);
    }

    std::vector<std::vector<FieldT>> tree_cols;

    for(size_t i=0; i < tree_matrix.size(); ++i)
    {
        std::vector<FieldT> tcol(tree_matrix[i].begin(), tree_matrix[i].end());
        tcol.resize(n, FieldT::zero());
        tree_cols.emplace_back(tcol);
    }

    return tree_cols;
}

template<typename FieldT>
std::tuple<std::vector<FieldT>, std::vector<FieldT>>
generate_data_vector(size_t n, size_t d, const std::vector<std::vector<FieldT>>& lagrangian_basis)
{
    std::vector<std::vector<uint64_t> > test_data = {
        {0, 35, 45, 20, 16, 80, 100, 47},
        {0, 23, 105, 110, 200, 12, 50, 12},
        {0, 78, 23, 45, 20, 10, 23, 45, 13},
        {0, 110, 123, 20, 10, 55, 89, 12},
        {0, 35, 45, 20, 16, 80, 100, 47},
        {0, 23, 105, 110, 200, 12, 50, 12},
        {0, 78, 23, 45, 20, 10, 23, 45, 13},
        {0, 110, 123, 20, 10, 55, 89, 12}
    };

    std::vector<std::vector<uint64_t>> test_data_dup;
    for(size_t i=0; i < n; ++i)
    {
        test_data_dup.emplace_back(test_data[i % 8]);
    }

    for(size_t i=0; i < test_data_dup.size(); ++i)
        test_data_dup[i].resize(d, 0);
    
    std::vector<FieldT> data_vector;
    std::vector<FieldT> data_values;
    for(size_t i=0; i < n; ++i)
    {
        auto ipoly = interpolate_polynomial<FieldT>(test_data_dup[i], lagrangian_basis);
        assert(ipoly.size() == d);
        data_vector.insert(data_vector.end(), ipoly.begin(), ipoly.end());
        data_values.insert(data_values.end(), test_data_dup[i].begin(), test_data_dup[i].end());
    }

    return {data_vector, data_values};
}

template<typename FieldT>
void allocate_slot(protoboard<FieldT>& pb, pb_variable_array<FieldT>& v, size_t n, size_t slot_size, const std::string& annotation)
{
    v.allocate(pb, n, annotation);
    pb_variable_array<FieldT> dummy;
    dummy.allocate(pb, slot_size - n, "dummy");
    
    // zero out the slot
    for(size_t i=0; i < v.size(); ++i)
        pb.val(v[i]) = 0;
    for(size_t i=0; i < dummy.size(); ++i)
        pb.val(dummy[i]) = 0;

}

template<typename ppT, typename FieldT = libff::Fr<ppT>, typename CommT = knowledge_commitment<libff::G1<ppT>, libff::G2<ppT>> >
proto_stats execute_simultaneous_perm_proto
(
    const commitment_key<ppT>& ck,
    size_t slot_size,
    const std::vector<CommT>& comm_left,
    const std::vector<CommT>& comm_right,
    const std::vector<std::vector<FieldT>>& vecs_left,
    const std::vector<std::vector<FieldT>>& vecs_right,
    const std::vector<FieldT>& rand_left,
    const std::vector<FieldT>& rand_right
)
{
    CommT cm_left = CommT::zero();
    CommT cm_right = CommT::zero();

    // randomly sampled coefficients for linear combination
    std::vector<FieldT> alpha(vecs_left.size());

    FieldT rL = FieldT::zero();
    FieldT rR = FieldT::zero();

    for(size_t i=0; i < alpha.size(); ++i)
        alpha[i] = FieldT::random_element();

    for(size_t i=0; i < rand_left.size(); ++i)
    {
        cm_left = cm_left + (alpha[i] * comm_left[i]);
        rL = rL + (alpha[i] * rand_left[i]);
    }

    for(size_t i=0; i < rand_right.size(); ++i)
    {
        cm_right = cm_right + (alpha[i] * comm_right[i]);
        rR = rR + (alpha[i] * rand_right[i]);
    }


    std::vector<FieldT> X(vecs_left[0].size(), FieldT::zero());
    std::vector<FieldT> Y(vecs_right[0].size(), FieldT::zero());

    for(size_t i=0; i < X.size(); ++i)
        for(size_t j=0; j < alpha.size(); ++j)
            X[i] = X[i] + alpha[j] * vecs_left[j][i];
    
    for(size_t i=0; i < Y.size(); ++i)
        for(size_t j=0; j < alpha.size(); ++j)
            Y[i] = Y[i] + alpha[j] * vecs_right[j][i];


    protoboard<FieldT> pb2;
    pb_variable<FieldT> challenge;
    pb_variable_array<FieldT> input, output;
    FieldT beta = FieldT::random_element(); // random challenge for polynomial identity test
    long long start, end;
    proto_stats run_stats;

    challenge.allocate(pb2, "challenge");
    allocate_slot(pb2, input, X.size(), slot_size, "input");
    allocate_slot(pb2, output, Y.size(), slot_size, "output");

    interactive_permutation_gadget<FieldT> permutation_gadget(pb2, challenge, input, output, "permutation test");
    permutation_gadget.generate_r1cs_constraints();

    // generate witness
    input.fill_with_field_elements(pb2, X);
    output.fill_with_field_elements(pb2, Y);
    pb2.val(challenge) = beta;

    permutation_gadget.generate_r1cs_witness();
    pb2.set_input_sizes(1);

    // generate keys for permutation gadget
    start = libff::get_nsec_time();
    r1cs_adaptive_snark_keypair<snark_pp> key2 = r1cs_adaptive_snark_generator(
        pb2.get_constraint_system(),
        ck,
        2,
        slot_size);
    end = libff::get_nsec_time();
    run_stats.generator_time = (end - start)/1000000000;

    auto randomness = {rL, rR};
    auto comms = {cm_left, cm_right};

    start = libff::get_nsec_time();
    auto proof2 = r1cs_adaptive_snark_prover(
        key2.pk,
        pb2.primary_input(),
        pb2.auxiliary_input(),
        randomness,
        2,
        slot_size);
    end = libff::get_nsec_time();
    run_stats.prover_time = (end - start) / 1000000000;

    start = libff::get_nsec_time();
    bool ok2 = r1cs_adaptive_snark_verifier(
        key2.vk,
        pb2.primary_input(),
        comms,
        2,
        slot_size,
        proof2);
    end = libff::get_nsec_time();
    run_stats.verifier_time = (end - start) / 1000000;
    run_stats.num_constraints = pb2.num_constraints();
    run_stats.status = ok2;

    return run_stats;
}

template<typename ppT, typename FieldT = libff::Fr<ppT>, typename CommT = knowledge_commitment<libff::G1<ppT>, libff::G2<ppT>> >
proto_stats execute_interactive_lookup_proto
(
    const commitment_key<ppT>& ck,
    size_t slot_size,
    const std::vector<CommT>& commited_input,
    const std::vector<FieldT>& L,
    const std::vector<FieldT>& U,
    const std::vector<FieldT>& V,
    const FieldT rL,
    const FieldT rU,
    const FieldT rV
)
{
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

    // compute commitments
    auto cm_L = commited_input[0];
    auto cm_U = commited_input[1];
    auto cm_V = commited_input[2];
    auto cm_uL = compute_commitment(ck, uL, ruL);
    auto cm_vL = compute_commitment(ck, vL, rvL);
    auto cm_uR = compute_commitment(ck, uR, ruR);
    auto cm_vR = compute_commitment(ck, vR, rvR);

    auto rand_vec = {rL, rU, rV, ruL, rvL, ruR, rvR};
    auto cm_vec = {cm_L, cm_U, cm_V, cm_uL, cm_vL, cm_uR, cm_vR};

    proto_stats lookup_stats;
    long long start, end;

    // generate proof for first step of the protocol
    start = libff::get_nsec_time();
    r1cs_adaptive_snark_keypair<snark_pp> key = r1cs_adaptive_snark_generator(
        pb.get_constraint_system(),
        ck,
        7,
        slot_size);
    end = libff::get_nsec_time();
    lookup_stats.generator_time = (end - start)/1000000000; // generator time in seconds
    
    start = libff::get_nsec_time();
    auto proof = r1cs_adaptive_snark_prover(
        key.pk,
        pb.primary_input(),
        pb.auxiliary_input(),
        rand_vec,
        7,
        slot_size);

    end = libff::get_nsec_time();
    lookup_stats.prover_time = (end - start) / 1000000000; // prover time in seconds

    start = libff::get_nsec_time();
    bool ok = r1cs_adaptive_snark_verifier(
        key.vk,
        pb.primary_input(),
        cm_vec,
        7,
        slot_size,
        proof);
    end = libff::get_nsec_time();

    lookup_stats.verifier_time = (end - start) / 1000000; // verifier time in milliseconds
    lookup_stats.num_constraints = pb.num_constraints();
    lookup_stats.status = ok;

    // now run the simultaneous permutation sub-protocol
    std::vector<CommT> cm_left = {cm_uL, cm_vL};
    std::vector<CommT> cm_right = {cm_uR, cm_vR};
    std::vector<std::vector<FieldT>> vecs_left = {uL, vL};
    std::vector<std::vector<FieldT>> vecs_right = {uR, vR};
    std::vector<FieldT> rand_left = {ruL, rvL};
    std::vector<FieldT> rand_right = {ruR, rvR};

    auto sub_proto_stats = execute_simultaneous_perm_proto<snark_pp>(ck, slot_size, cm_left, cm_right, vecs_left, vecs_right, rand_left, rand_right);
    lookup_stats.prover_time += sub_proto_stats.prover_time;
    lookup_stats.verifier_time += sub_proto_stats.verifier_time;
    lookup_stats.status &= sub_proto_stats.status;
    lookup_stats.num_constraints += sub_proto_stats.num_constraints;

    return lookup_stats;
}

void run_interactive_lookup()
{
    snark_pp::init_public_params();
    typedef libff::Fr<snark_pp> FieldT;
    
    size_t N = 1000; // size of the table
    size_t slot_size;

    std::ofstream ofile("interactive-lookup-benchmark-new.txt");
    ofile << "N = " << N << std::endl;

    // m = number of lookups
    std::vector<size_t> mvalues = {100, 1000, 10000, 100000};
    for(size_t tn=0; tn < mvalues.size(); ++tn)
    {
        size_t m = mvalues[tn];
        slot_size = m + N + 1;
        commitment_key<snark_pp> ck;
        ck.sample(1+slot_size);

        std::vector<FieldT> L, U, V;
        for(size_t i=0; i < N; ++i)
            L.emplace_back(2*i);
        
        for(size_t i=0; i < m; ++i)
            U.emplace_back(get_random_value(N));
        
        for(size_t i=0; i < m; ++i)
        {
            V.emplace_back(L[ U[i].as_ulong() ]);
        }

        FieldT rL = FieldT::random_element();
        FieldT rU = FieldT::random_element();
        FieldT rV = FieldT::random_element();

        auto cm_L = compute_commitment(ck, L, rL);
        auto cm_U = compute_commitment(ck, U, rU);
        auto cm_V = compute_commitment(ck, V, rV);
        std::vector<knowledge_commitment<libff::G1<snark_pp>, libff::G2<snark_pp>>> cm_vec = {cm_L, cm_U, cm_V};

        proto_stats run_stats = execute_interactive_lookup_proto<snark_pp>(ck, slot_size, cm_vec, L, U, V, rL, rU, rV);
        ofile << run_stats.prover_time << " " << run_stats.verifier_time << " " << run_stats.num_constraints << " " << run_stats.status << std::endl;
    }

}

void run_interactive_filter_proto()
{
    snark_pp::init_public_params();
    typedef libff::Fr<snark_pp> FieldT;

    size_t slot_size;

    std::ofstream ofile("filter-benchmarks.txt");

    long long start, end;

    std::vector<size_t> Nvalues = {100, 1000, 10000, 100000, 1000000};

    for(size_t tn = 0; tn < Nvalues.size(); tn++)
    {
        size_t N = Nvalues[tn];
        slot_size = N+10;
        commitment_key<snark_pp> ck;
        ck.sample(1+slot_size);

        auto example = generate_filter_example(N);

        protoboard<FieldT> pb;
        // allocate commitment slots
        pb_variable_array<FieldT> x, f, y, tilde_f, U, delta, V;

        allocate_slot(pb, x, N+1, slot_size, "x");
        allocate_slot(pb, f, N, slot_size, "f");
        allocate_slot(pb, y, N+1, slot_size, "y");
        allocate_slot(pb, tilde_f, N, slot_size, "tilde_f");
        allocate_slot(pb, U, N, slot_size, "U");
        allocate_slot(pb, delta, N, slot_size, "delta");
        allocate_slot(pb, V, N, slot_size, "V");

        cp_filter_gadget<FieldT> filter_gadget(pb, x, f, y, tilde_f, U, delta, V);
        filter_gadget.generate_r1cs_constraints();

        // set the values of vectors x, f and y
        std::vector<FieldT> xv, fv, yv;
        xv.emplace_back(example.source.size());
        yv.emplace_back(example.target.size());

        xv.insert(xv.end(), example.source.begin(), example.source.end());
        yv.insert(yv.end(), example.target.begin(), example.target.end());
        fv.insert(fv.end(), example.f.begin(), example.f.end());
        xv.resize(N+1, FieldT::zero());
        yv.resize(N+1, FieldT::zero());
        fv.resize(N, FieldT::zero());

        x.fill_with_field_elements(pb, xv);
        y.fill_with_field_elements(pb, yv);
        f.fill_with_field_elements(pb, fv);

        filter_gadget.generate_r1cs_witness();

        // sample randomness to commit the vectors
        auto r_x = FieldT::random_element();
        auto r_y = FieldT::random_element();
        auto r_f = FieldT::random_element();
        auto r_tilde_f = FieldT::random_element();
        auto r_U = FieldT::random_element();
        auto r_delta = FieldT::random_element();
        auto r_V = FieldT::random_element();

        // get output vectors
        auto val_tilde_f = tilde_f.get_vals(pb);
        auto val_U = U.get_vals(pb);
        auto val_delta = delta.get_vals(pb);
        auto val_V = V.get_vals(pb);

        // compute commitments
        auto cm_x = compute_commitment(ck, xv, r_x);
        auto cm_y = compute_commitment(ck, yv, r_y);
        auto cm_f = compute_commitment(ck, fv, r_f);
        auto cm_tilde_f = compute_commitment(ck, val_tilde_f, r_tilde_f);
        auto cm_U = compute_commitment(ck, val_U, r_U);
        auto cm_delta = compute_commitment(ck, val_delta, r_delta);
        auto cm_V = compute_commitment(ck, val_V, r_V);

        auto rand_vec = {r_x, r_f, r_y, r_tilde_f, r_U, r_delta, r_V};
        auto comm_vec = {cm_x, cm_f, cm_y, cm_tilde_f, cm_U, cm_delta, cm_V};

        // generate proof for first step of the protocol
        r1cs_adaptive_snark_keypair<snark_pp> key = r1cs_adaptive_snark_generator(
            pb.get_constraint_system(),
            ck,
            7,
            slot_size);
        
        start = libff::get_nsec_time();
        auto proof = r1cs_adaptive_snark_prover(
            key.pk,
            pb.primary_input(),
            pb.auxiliary_input(),
            rand_vec,
            7,
            slot_size
        );
        end = libff::get_nsec_time();
        auto prover_time = (end - start)/1000000000;

        start = libff::get_nsec_time();
        bool ok = r1cs_adaptive_snark_verifier(
            key.vk,
            pb.primary_input(),
            comm_vec,
            7,
            slot_size,
            proof
        );
        end = libff::get_nsec_time();
        auto verifier_time = (end - start)/1000000;

        // prove simultaneous permutation between (tilde_f, U) and (delta, V)
        auto alpha = FieldT::random_element();
        auto beta = FieldT::random_element();

        // P & V compute
        auto cl = cm_tilde_f + alpha * cm_U;
        auto cr = cm_delta +  alpha * cm_V;

        auto rl = r_tilde_f + alpha * r_U;
        auto rr = r_delta + alpha * r_V;

        protoboard<FieldT> pb2;
        
        pb_variable<FieldT> challenge;
        pb_variable_array<FieldT> input, output;

        challenge.allocate(pb2, "challenge");
        allocate_slot(pb2, input, N, slot_size, "input");
        allocate_slot(pb2, output, N, slot_size, "output");

        interactive_permutation_gadget<FieldT> permutation_gadget(pb2, challenge, input, output, "permutation test");
        permutation_gadget.generate_r1cs_constraints();

        // generate witness
        for(size_t i=0; i < input.size(); ++i)
        {
            pb2.val(input[i]) = pb.val(tilde_f[i]) + alpha * pb.val(U[i]);
            pb2.val(output[i]) = pb.val(delta[i]) + alpha * pb.val(V[i]);
        }

        pb2.val(challenge) = beta;

        permutation_gadget.generate_r1cs_witness();
        pb2.set_input_sizes(1);

        // generate keys for permutation gadget
        r1cs_adaptive_snark_keypair<snark_pp> key2 = r1cs_adaptive_snark_generator(
        pb2.get_constraint_system(),
        ck,
        2,
        slot_size); 
        
        auto randomness2 = {rl, rr};
        auto comms2 = {cl, cr};

        start = libff::get_nsec_time();
        auto proof2 = r1cs_adaptive_snark_prover(
            key2.pk,
            pb2.primary_input(),
            pb2.auxiliary_input(),
            randomness2,
            2,
            slot_size            
        );
        end = libff::get_nsec_time();
        auto prover_time2 = (end - start)/1000000000;


        start = libff::get_nsec_time();
        bool ok2 = r1cs_adaptive_snark_verifier(
            key2.vk,
            pb2.primary_input(),
            comms2,
            2,
            slot_size,
            proof2
        );
        end = libff::get_nsec_time();
        auto verifier_time2 = (end - start)/1000000;


        ofile << N << " " << prover_time << " " << 
            prover_time2 << " " << verifier_time << " " << verifier_time2 << " " << 
            pb.num_constraints() << " " << pb2.num_constraints() << " " 
            << ok << " " << ok2 << std::endl;

    }
}

void run_interactive_inner_join_proto()
{
    snark_pp::init_public_params();
    typedef libff::Fr<snark_pp> FieldT;
    typedef knowledge_commitment<libff::G1<snark_pp>, libff::G2<snark_pp>> CommT;
    
    std::ofstream ofile("inner-join-benchmarks.txt");
    std::vector<size_t> Nvalues = {100, 1000, 10000, 100000};

    for (size_t tn = 0; tn < Nvalues.size(); tn++)
    {
        size_t N = Nvalues[tn];
        size_t slot_size = 2 * N + 1;

        // get commitment key
        commitment_key<snark_pp> ck;
        ck.sample(slot_size + 1);
        long long start, end;

        std::vector<size_t> x = {5, 10, 20, 30, 40, 50, 99, 99, 99, 99, 99};
        std::vector<size_t> y = {5, 1, 2, 3, 4, 5, 99, 99, 99, 99, 99};
        std::vector<size_t> z = {4, 2, 4, 6, 8, 99, 99, 99, 99, 99, 99};
        std::vector<size_t> w = {4, 15, 30, 45, 60, 99, 99, 99, 99, 99, 99};

        x.resize(N + 1);
        y.resize(N + 1);
        z.resize(N + 1);
        w.resize(N + 1);

        merge_transcript tr = generate_merge_transcript(x, y, z, w);

        protoboard<FieldT> pb;

        std::vector<FieldT> vals_x(x.begin(), x.end());
        std::vector<FieldT> vals_y(y.begin(), y.end());
        std::vector<FieldT> vals_z(z.begin(), z.end());
        std::vector<FieldT> vals_w(w.begin(), w.end());

        std::vector<FieldT> vals_tr_X(tr.tr_X.begin(), tr.tr_X.end());
        std::vector<FieldT> vals_tr_Y(tr.tr_Y.begin(), tr.tr_Y.end());
        std::vector<FieldT> vals_tr_Z(tr.tr_Z.begin(), tr.tr_Z.end());
        std::vector<FieldT> vals_tr_W(tr.tr_W.begin(), tr.tr_W.end());
        std::vector<FieldT> vals_tr_I(tr.tr_I.begin(), tr.tr_I.end());
        std::vector<FieldT> vals_tr_J(tr.tr_J.begin(), tr.tr_J.end());
        std::vector<FieldT> vals_tr_O(tr.tr_O.begin(), tr.tr_O.end());
        std::vector<FieldT> vals_tr_S(tr.tr_S.begin(), tr.tr_S.end());

        std::vector<FieldT> vals_p, vals_q, vals_r;
        vals_p.emplace_back(tr.p.size());
        vals_q.emplace_back(tr.q.size());
        vals_r.emplace_back(tr.r.size());

        vals_p.insert(vals_p.end(), tr.p.begin(), tr.p.end());
        vals_q.insert(vals_q.end(), tr.q.begin(), tr.q.end());
        vals_r.insert(vals_r.end(), tr.r.begin(), tr.r.end());

        vals_p.resize(N + 1, FieldT::zero());
        vals_q.resize(N + 1, FieldT::zero());
        vals_r.resize(N + 1, FieldT::zero());

        // declare protoboard variables
        pb_variable_array<FieldT> pb_x, pb_y, pb_z, pb_w, pb_tr_X, pb_tr_Y;
        pb_variable_array<FieldT> pb_tr_Z, pb_tr_W, pb_tr_I, pb_tr_J, pb_tr_O, pb_tr_S;
        pb_variable_array<FieldT> pb_p, pb_q, pb_r;
        pb_variable_array<FieldT> pb_tilde_delta, pb_tilde_p, pb_tilde_q, pb_tilde_r;

        allocate_slot(pb, pb_x, N + 1, slot_size, "pb_x");
        allocate_slot(pb, pb_y, N + 1, slot_size, "pb_y");
        allocate_slot(pb, pb_z, N + 1, slot_size, "pb_z");
        allocate_slot(pb, pb_w, N + 1, slot_size, "pb_w");
        // p, q, r
        allocate_slot(pb, pb_p, N + 1, slot_size, "pb_p");
        allocate_slot(pb, pb_q, N + 1, slot_size, "pb_q");
        allocate_slot(pb, pb_r, N + 1, slot_size, "pb_r");

        // transcript
        allocate_slot(pb, pb_tr_X, 2 * N, slot_size, "pb_tr_X");
        allocate_slot(pb, pb_tr_Y, 2 * N, slot_size, "pb_tr_Y");
        allocate_slot(pb, pb_tr_Z, 2 * N, slot_size, "pb_tr_Z");
        allocate_slot(pb, pb_tr_W, 2 * N, slot_size, "pb_tr_W");
        allocate_slot(pb, pb_tr_I, 2 * N, slot_size, "pb_tr_I");
        allocate_slot(pb, pb_tr_J, 2 * N, slot_size, "pb_tr_J");
        allocate_slot(pb, pb_tr_O, 2 * N, slot_size, "pb_tr_O");
        allocate_slot(pb, pb_tr_S, 2 * N, slot_size, "pb_tr_S");

        // outputs
        allocate_slot(pb, pb_tilde_delta, 2 * N, slot_size, "pb_tilde_delta");
        allocate_slot(pb, pb_tilde_p, 2 * N, slot_size, "pb_tilde_p");
        allocate_slot(pb, pb_tilde_q, 2 * N, slot_size, "pb_tilde_q");
        allocate_slot(pb, pb_tilde_r, 2 * N, slot_size, "pb_tilde_r");

        cp_inner_join_gadget<FieldT> join_gadget(pb, 32,
                                                 pb_x, pb_y, pb_z, pb_w,
                                                 pb_p, pb_q, pb_r,
                                                 pb_tr_X, pb_tr_Y, pb_tr_Z, pb_tr_W,
                                                 pb_tr_I, pb_tr_J, pb_tr_O, pb_tr_S,
                                                 pb_tilde_delta, pb_tilde_p, pb_tilde_q, pb_tilde_r,
                                                 "join gadget");

        join_gadget.generate_r1cs_constraints();

        // generate witness
        pb_x.fill_with_field_elements(pb, vals_x);
        pb_y.fill_with_field_elements(pb, vals_y);
        pb_z.fill_with_field_elements(pb, vals_z);
        pb_w.fill_with_field_elements(pb, vals_w);
        pb_p.fill_with_field_elements(pb, vals_p);
        pb_q.fill_with_field_elements(pb, vals_q);
        pb_r.fill_with_field_elements(pb, vals_r);

        pb_tr_X.fill_with_field_elements(pb, vals_tr_X);
        pb_tr_Y.fill_with_field_elements(pb, vals_tr_Y);
        pb_tr_Z.fill_with_field_elements(pb, vals_tr_Z);
        pb_tr_W.fill_with_field_elements(pb, vals_tr_W);
        pb_tr_I.fill_with_field_elements(pb, vals_tr_I);
        pb_tr_J.fill_with_field_elements(pb, vals_tr_J);
        pb_tr_O.fill_with_field_elements(pb, vals_tr_O);
        pb_tr_S.fill_with_field_elements(pb, vals_tr_S);

        join_gadget.generate_r1cs_witness();

        // ouput vectors of the inner join gadget
        std::vector<FieldT> vals_tilde_delta, vals_tilde_p, vals_tilde_q, vals_tilde_r;
        vals_tilde_delta = pb_tilde_delta.get_vals(pb);
        vals_tilde_p = pb_tilde_p.get_vals(pb);
        vals_tilde_q = pb_tilde_q.get_vals(pb);
        vals_tilde_r = pb_tilde_r.get_vals(pb);


        std::vector<FieldT> rand_vec;
        for (size_t i = 0; i < 19; ++i)
            rand_vec.emplace_back(FieldT::random_element());
        
        // compute commitments for each of the commitment slots
        auto cm_x = compute_commitment(ck, vals_x, rand_vec[0]);
        auto cm_y = compute_commitment(ck, vals_y, rand_vec[1]);
        auto cm_z = compute_commitment(ck, vals_z, rand_vec[2]);
        auto cm_w = compute_commitment(ck, vals_w, rand_vec[3]);
        auto cm_p = compute_commitment(ck, vals_p, rand_vec[4]);
        auto cm_q = compute_commitment(ck, vals_q, rand_vec[5]);
        auto cm_r = compute_commitment(ck, vals_r, rand_vec[6]);
        
        auto cm_tr_X = compute_commitment(ck, vals_tr_X, rand_vec[7]);
        auto cm_tr_Y = compute_commitment(ck, vals_tr_Y, rand_vec[8]);
        auto cm_tr_Z = compute_commitment(ck, vals_tr_Z, rand_vec[9]);
        auto cm_tr_W = compute_commitment(ck, vals_tr_W, rand_vec[10]);
        auto cm_tr_I = compute_commitment(ck, vals_tr_I, rand_vec[11]);
        auto cm_tr_J = compute_commitment(ck, vals_tr_J, rand_vec[12]);
        auto cm_tr_O = compute_commitment(ck, vals_tr_O, rand_vec[13]);
        auto cm_tr_S = compute_commitment(ck, vals_tr_S, rand_vec[14]);

        auto cm_tilde_delta = compute_commitment(ck, vals_tilde_delta, rand_vec[15]);
        auto cm_tilde_p = compute_commitment(ck, vals_tilde_p, rand_vec[16]);
        auto cm_tilde_q = compute_commitment(ck, vals_tilde_q, rand_vec[17]);
        auto cm_tilde_r = compute_commitment(ck, vals_tilde_r, rand_vec[18]);

        auto cm_vec = {cm_x, cm_y, cm_z, cm_w, cm_p, cm_q, cm_r, cm_tr_X, cm_tr_Y, cm_tr_Z, cm_tr_W,
                        cm_tr_I, cm_tr_J, cm_tr_O, cm_tr_S, cm_tilde_delta, cm_tilde_p, cm_tilde_q, cm_tilde_r};



        // generate keys
        r1cs_adaptive_snark_keypair<snark_pp> key = r1cs_adaptive_snark_generator(
            pb.get_constraint_system(),
            ck,
            19,
            slot_size);

        start = libff::get_nsec_time();
        auto proof = r1cs_adaptive_snark_prover(
            key.pk,
            pb.primary_input(),
            pb.auxiliary_input(),
            rand_vec,
            19,
            slot_size);
        end = libff::get_nsec_time();
        auto prover_time = (end - start) / 1000000000;

        start = libff::get_nsec_time();
        bool ok = r1cs_adaptive_snark_verifier(
            key.vk,
            pb.primary_input(), 
            cm_vec, 
            19, 
            slot_size,
            proof);
        end = libff::get_nsec_time();
        auto verifier_time = (end - start)/1000000;

        // add the lookup subprotocols
        proto_stats lookup1_stats, lookup2_stats;
        FieldT gamma = FieldT::random();
        // Use gamma to combine the lookups with same access patterns I and J
        // vals_x and vals_y and indexed using I
        // vals_z and vals_w are indexed using J
        std::vector<FieldT> L1(vals_x.size()), L2(vals_z.size());
        std::vector<FieldT> V1(vals_tr_X.size()), V2(vals_tr_Y.size());

        for(size_t i=0; i < L1.size(); ++i)
        {
            L1[i] = vals_x[i] + (gamma * vals_y[i]);
            L2[i] = vals_z[i] + (gamma * vals_w[i]);
        }

        for(size_t i=0; i < V1.size(); ++i)
        {
            V1[i] = vals_tr_X[i] + (gamma * vals_tr_Y[i]);
            V2[i] = vals_tr_Z[i] + (gamma * vals_tr_W[i]);
        }

        CommT cm_L_1 = cm_x + gamma * cm_y;
        CommT cm_L_2 = cm_z + gamma * cm_w;
        CommT cm_V_1 = cm_tr_X + gamma * cm_tr_Y;
        CommT cm_V_2 = cm_tr_Z + gamma * cm_tr_W;

        FieldT rL_1 = rand_vec[0] + gamma * rand_vec[1]; // corresponding to x + \gamma. y
        FieldT rL_2 = rand_vec[2] + gamma * rand_vec[3]; // corr. to z + \gamma. w
        FieldT rV_1 = rand_vec[7] + gamma * rand_vec[8];
        FieldT rV_2 = rand_vec[9] + gamma * rand_vec[10];
        FieldT rU_1 = rand_vec[11];
        FieldT rU_2 = rand_vec[12];
        std::vector<CommT> cm_vec_1 = {cm_L_1, cm_U_1, cm_V_1};
        std::vector<CommT> cm_vec_2 = {cm_L_2, cm_U_2, cm_V_2};

        lookup1_stats = execute_interactive_lookup_proto<snark_pp>(
            ck,
            slot_size,
            cm_vec_1,
            L1, vals_tr_I, V1,
            rL_1, rU_1, rV_1
        );

        lookup2_stats = execute_interactive_lookup_proto<snark_pp>(
            ck,
            slot_size,
            cm_vec_2,
            L2, vals_tr_J, V2,
            rL_2, rU_2, rV_2
        );

        long long t_prover_time = prover_time + lookup1_stats.prover_time + lookup2_stats.prover_time;
        long long t_verifier_time = verifier_time + lookup1_stats.verifier_time + lookup2_stats.verifier_time;
        bool status = ok & lookup1_stats.status & lookup2_stats.status;
        long long t_constraints = pb.num_constraints() + 2 * lookup1_stats.num_constraints;

        ofile << N << " " << t_prover_time << " " << t_verifier_time << " " << t_constraints << " " << status << std::endl;

    }
}

void run_interactive_decision_tree_proto()
{
    snark_pp::init_public_params();
    typedef libff::Fr<snark_pp> FieldT;

    size_t N = 1000;
    size_t h = 10;
    size_t d = 50;
    size_t bit_width = 32;

    auto tree_cols = generate_decision_tree<FieldT>(N);
    auto lagrangian_basis = compute_lagrange_polynomials<FieldT>(d);
    long long start, end;

    std::ofstream ofile("interactive-decision-tree-benchmarks-shallow.txt");

    std::vector<size_t> nvalues = {100, 1000, 5000};

    for(size_t tn = 0; tn < 3; tn++)
    {
        size_t n = nvalues[tn];
        size_t slot_size = h*n + 1;
        commitment_key<snark_pp> ck;
        ck.sample(1 + slot_size);

        std::vector<FieldT> data_vector = std::get<0>(generate_data_vector<FieldT>(n, d, lagrangian_basis));

        protoboard<FieldT> pb;

        pb_variable_array<FieldT> data, predictions, V, T, L, R, C;
        pb_variable_array<FieldT> p, f, t, l, r, c, v;

        data.allocate(pb, d*n, "data");
        predictions.allocate(pb, n, "predictions");

        allocate_slot(pb, V, N, slot_size, "p");
        allocate_slot(pb, T, N, slot_size, "f");
        allocate_slot(pb, L, N, slot_size, "t");
        allocate_slot(pb, R, N, slot_size, "l");
        allocate_slot(pb, C, N, slot_size, "r");

        allocate_slot(pb, p, h*n, slot_size, "p");
        allocate_slot(pb, f, h*n, slot_size, "f");
        allocate_slot(pb, t, h*n, slot_size, "t");
        allocate_slot(pb, l, h*n, slot_size, "l");
        allocate_slot(pb, r, h*n, slot_size, "r");
        allocate_slot(pb, c, h*n, slot_size, "c");



        cp_decision_tree_gadget<FieldT> decision_tree(pb, h, bit_width, d, n, 
            data, predictions,
            V, T, L, R, C,
            p, f, t, l, r, c
        );

        decision_tree.generate_r1cs_constraints();

        // compute witness
        data.fill_with_field_elements(pb, data_vector);
        V.fill_with_field_elements(pb, tree_cols[1]);
        T.fill_with_field_elements(pb, tree_cols[2]);
        L.fill_with_field_elements(pb, tree_cols[3]);
        R.fill_with_field_elements(pb, tree_cols[4]);
        C.fill_with_field_elements(pb, tree_cols[5]);

        decision_tree.generate_r1cs_witness();

        pb.set_input_sizes(d*n + n); // data + predictions are public
        std::vector<FieldT> rand_vec;
        for(size_t i=0; i < 11; ++i)
            rand_vec.emplace_back(FieldT::random_element());
        

        // generate keys
        r1cs_adaptive_snark_keypair<snark_pp> key = r1cs_adaptive_snark_generator(
            pb.get_constraint_system(),
            ck,
            11,
            slot_size);

        start = libff::get_nsec_time();
        auto proof = r1cs_adaptive_snark_prover(
            key.pk,
            pb.primary_input(),
            pb.auxiliary_input(),
            rand_vec,
            11,
            slot_size);

        end = libff::get_nsec_time();
        auto prover_time = (end - start) / 1000000000;

        ofile << n << " " << prover_time << " " << pb.num_constraints() << std::endl;
    }

}


int main(int argc, char *argv[])
{
    //run_interactive_lookup_proto();
    //run_interactive_filter_proto();
    //run_interactive_inner_join_proto();
    run_interactive_lookup();
    //run_interactive_decision_tree_proto();
    return 0;
}