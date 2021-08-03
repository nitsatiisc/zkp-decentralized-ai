#ifndef __TRUSTED_AI_TRAPDOOR_COMMITMENT__
#define __TRUSTED_AI_TRAPDOOR_COMMITMENT__


#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>

using namespace libsnark;

namespace TrustedAI {

template<typename ppT>
class commitment_key {
    public:
    knowledge_commitment_vector<libff::G1<ppT>, libff::G2<ppT>> key_;
    size_t key_size_;
    libff::Fr<ppT> s;
    libff::Fr<ppT> alpha;

    commitment_key() {};
    // sample a key
    void sample(size_t key_size);

    // serialize the key
    void serialize(std::ostream& out);

    // deserialize the key
    void deserialize(std::istream& inp);

};

template<typename ppT>
void commitment_key<ppT>::sample(size_t key_size)
{
    key_size_ = key_size;
    s = libff::Fr<ppT>::random_element();
    alpha = libff::Fr<ppT>::random_element();

    std::vector<libff::Fr<ppT>> St;
    St.emplace_back(libff::Fr<ppT>::one());

    libff::Fr<ppT> x = libff::Fr<ppT>::one();
    for(size_t i=0; i < key_size_; ++i)
    {
        x = x * s;
        St.emplace_back(x);
    }
    
    std::vector<knowledge_commitment<libff::G1<ppT>, libff::G2<ppT> > > key_vector;
    size_t g1_window = libff::get_exp_window_size<libff::G1<ppT> >(key_size_);
    size_t g2_window = libff::get_exp_window_size<libff::G2<ppT> >(key_size_);
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

    libff::enter_block("Generate Commitment Key");

    libff::enter_block("Generate knowledge commitments");
    libff::enter_block("Compute the Comm-query", false);
    key_ = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g1_window, g2_window, g1_table, g2_table, libff::Fr<ppT>::one(), alpha, St, chunks);
    libff::leave_block("Compute the Comm-query", false);
}

template<typename ppT>
void commitment_key<ppT>::serialize(std::ostream& out)
{
    out << key_size_ << OUTPUT_NEWLINE << key_ << OUTPUT_NEWLINE;
}

template<typename ppT>
void commitment_key<ppT>::deserialize(std::istream& inp)
{
    inp >> key_size_;
    libff::consume_OUTPUT_NEWLINE(inp);
    inp >> key_;
    libff::consume_OUTPUT_NEWLINE(inp);
}


template<typename ppT>
knowledge_commitment<libff::G1<ppT>, libff::G2<ppT> > 
compute_commitment(
    const commitment_key<ppT>& ck, 
    const std::vector<libff::Fr<ppT> >& v, 
    libff::Fr<ppT> r)
{
    std::vector<libff::Fr<ppT>> V;
    V.emplace_back(r);
    V.insert(V.end(), v.begin(), v.end());


#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute the commitment", false);
    knowledge_commitment<libff::G1<ppT>, libff::G2<ppT> > comm = kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G2<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        ck.key_,
        0, V.size(),
        V.begin(), V.end(),
        chunks);
    libff::leave_block("Compute commitment", false);

    return comm;

}

template<typename ppT>
bool verify_commitment(
    const commitment_key<ppT>& ck,
    const knowledge_commitment<libff::G1<ppT>, libff::G2<ppT>>& comm,
    const std::vector<libff::Fr<ppT>>& v,
    const libff::Fr<ppT>& r
)
{
    libff::enter_block("Verify commitment opening", false);
    std::vector<libff::Fr<ppT>> V;
    V.emplace_back(r);
    V.insert(V.end(), v.begin(), v.end()); 
   
#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    knowledge_commitment<libff::G1<ppT>, libff::G2<ppT> > comm_v_r = kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                 libff::G2<ppT>,
                                                 libff::Fr<ppT>,
                                                 libff::multi_exp_method_bos_coster>(
        ck.key_,
        0, V.size(),
        V.begin(), V.end(),
        chunks); 
    
    return (comm == comm_v_r);
}

} // namespace




#endif
