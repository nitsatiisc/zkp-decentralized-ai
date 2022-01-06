#ifndef __TRUSTED_AI_INTERACTIVE_GADGETS__
#define __TRUSTED_AI_INTERACTIVE_GADGETS__

#include <zkdoc/src/trusted_ai_utility_gadgets.hpp>

using namespace libsnark;

namespace TrustedAI {

template<typename FieldT>
class interactive_permutation_gadget : public gadget<FieldT>
{

    public:
    interactive_permutation_gadget(
        protoboard<FieldT>& pb,
        const pb_variable<FieldT>& challenge,
        const pb_variable_array<FieldT>& input,
        const pb_variable_array<FieldT>& output,
        const std::string& annotation_prefix=""
    );

    void allocate() {};

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    private:
    pb_variable<FieldT> challenge_;
    pb_variable_array<FieldT> input_;
    pb_variable_array<FieldT> output_;

    pb_variable_array<FieldT> input_partial_products_;
    pb_variable_array<FieldT> output_partial_products_;

};

template<typename FieldT>
interactive_permutation_gadget<FieldT>::interactive_permutation_gadget(
    protoboard<FieldT>& pb,
    const pb_variable<FieldT>& challenge,
    const pb_variable_array<FieldT>& input,
    const pb_variable_array<FieldT>& output,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    challenge_(challenge),
    input_(input),
    output_(output)
{
    input_partial_products_.allocate(this->pb, input_.size(), "input_partial_products");
    output_partial_products_.allocate(this->pb, output_.size(), "output_partial_products");
}


template<typename FieldT>
void interactive_permutation_gadget<FieldT>::generate_r1cs_constraints()
{
    // input_partial_products_[k] = prod_{i=0}^k (challenge - input[i])
    // output_partial_products_[k] = prod_{i=0}^k (challenge - output[i])

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(challenge_ - input_[0], 1, input_partial_products_[0]),
        FMT(this->annotation_prefix, "partial input products 0")
    );

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(challenge_ - output_[0], 1, output_partial_products_[0]),
        FMT(this->annotation_prefix, "partial output products 0")
    );

    for(size_t i=1; i < input_.size(); ++i)
    {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(challenge_ - input_[i], input_partial_products_[i-1], input_partial_products_[i]),
            FMT(this->annotation_prefix, "partial input products %zu", i));

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(challenge_ - output_[i], output_partial_products_[i-1], output_partial_products_[i]),
            FMT(this->annotation_prefix, "partial output products 0"));

    }

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            input_partial_products_[input_.size() - 1] - output_partial_products_[input_.size() - 1],
            1,
            0
        ), FMT(this->annotation_prefix, "check equal")
    );

}

template<typename FieldT>
void interactive_permutation_gadget<FieldT>::generate_r1cs_witness()
{
    // input_partial_products_[k] = prod_{i=0}^k (challenge - input[i])
    // output_partial_products_[k] = prod_{i=0}^k (challenge - output[i])

    this->pb.val(input_partial_products_[0]) = this->pb.val(challenge_) - this->pb.val(input_[0]);
    this->pb.val(output_partial_products_[0]) = this->pb.val(challenge_) - this->pb.val(output_[0]);

    for(size_t i=1; i < input_.size(); ++i)
    {
        this->pb.val(input_partial_products_[i]) = (this->pb.val(challenge_) - this->pb.val(input_[i])) * this->pb.val(input_partial_products_[i-1]);
        this->pb.val(output_partial_products_[i]) = (this->pb.val(challenge_) - this->pb.val(output_[i])) * this->pb.val(output_partial_products_[i-1]);
    }

}

template<typename FieldT>
class interactive_lookup_arithmetic : public gadget<FieldT> 
{
    public:
    interactive_lookup_arithmetic(
        protoboard<FieldT>& pb,
        const pb_variable_array<FieldT>& L,
        const pb_variable_array<FieldT>& U,
        const pb_variable_array<FieldT>& V,
        const pb_variable_array<FieldT>& u,
        const pb_variable_array<FieldT>& v,
        const pb_variable_array<FieldT>& sorted_u,
        const pb_variable_array<FieldT>& perm_v,
        const std::string& annotation_prefix=""
    );

    void allocate() {};

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    private:
    pb_variable_array<FieldT> L_, U_, V_, u_, v_, sorted_u_, perm_v_;
    pb_variable_array<FieldT> delta_;

    // Constraints:
    // u[i] = i for i=0,..,n-1
    // u[n+i] = U[i] for i=0,...,m-1
    // v[i] = L[i] for i=0,...,n-1
    // v[n+i] = V[i] for i=0,...,m-1
    // delta[i] * delta[i] = delta[i] for i=0,...,m+n-2
    // u_sorted[i+1] = u_sorted[i] + delta[i] for i=0,...,m+n-2
    // (u_sorted[i+1] - u_sorted[i] - 1) * (v_perm[i+1] - v_perm[i]) = 0 for i=0,...,m+n-1
};

template<typename FieldT>
interactive_lookup_arithmetic<FieldT>::interactive_lookup_arithmetic(
    protoboard<FieldT>& pb,
    const pb_variable_array<FieldT>& L,
    const pb_variable_array<FieldT>& U,
    const pb_variable_array<FieldT>& V,
    const pb_variable_array<FieldT>& u,
    const pb_variable_array<FieldT>& v,
    const pb_variable_array<FieldT>& sorted_u,
    const pb_variable_array<FieldT>& perm_v,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    L_(L),
    U_(U),
    V_(V),
    u_(u), v_(v),
    sorted_u_(sorted_u),
    perm_v_(perm_v)
{
    size_t N = L_.size();
    size_t M = U_.size();
    assert(u_.size() == M+N);
    assert(v_.size() == M+N);
    assert(sorted_u_.size() == M+N);
    assert(perm_v_.size() == M+N);
    delta_.allocate(this->pb, M+N-1, "delta");

}

template<typename FieldT>
void interactive_lookup_arithmetic<FieldT>::generate_r1cs_constraints()
{
    size_t N = L_.size();
    size_t M = U_.size();

    // initial loading constraints
    for(size_t i=0; i < N; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                v_[i],
                1,
                L_[i]
            ), "load rom constraints"
        );

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                u_[i],
                1,
                i
            ), "initial address segment"
        );

    }

    // access constraints
    for(size_t i=0; i < M; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                v_[i+N],
                1,
                V_[i]
            ), "load values constraints"
        );

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                u_[i+N],
                1,
                U_[i]
            ), "load location constraints"
        );

    }

    // constraints on delta
    for(size_t i=0; i < delta_.size(); ++i)
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(delta_[i], delta_[i], delta_[i]), "delta booleanarity");

    for(size_t i=0; i < delta_.size(); ++i)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sorted_u_[i] + delta_[i], 1, sorted_u_[i+1]), "increment");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                sorted_u_[i+1] - sorted_u_[i] - 1,
                perm_v_[i+1] - perm_v_[i],
                0
            ), "lock-step-constraint"
        );
    }

    // establish boundary conditions
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sorted_u_[M+N-1],1,N-1),"boundary condition");
}

template<typename FieldT>
void interactive_lookup_arithmetic<FieldT>::generate_r1cs_witness()
{
    size_t N = L_.size();
    size_t M = U_.size();

    for(size_t i=0; i < N; ++i)
    {
        this->pb.val(u_[i]) = i;
        this->pb.val(v_[i]) = this->pb.val(L_[i]);
    }

    for(size_t i=0; i < M; ++i)
    {
        this->pb.val(u_[i+N]) = this->pb.val(U_[i]);
        this->pb.val(v_[i+N]) = this->pb.val(V_[i]);
    }

    std::vector<size_t> unsorted;
    for(size_t i=0; i < M+N; ++i)
        unsorted.emplace_back(static_cast<size_t>(this->pb.val(u_[i]).as_ulong()));
    
    std::vector<size_t> sorted = unsorted;
    std::sort(sorted.begin(), sorted.end());

    std::vector<size_t> perm = find_permutation_for_sort(unsorted, sorted);

    for(size_t i=0; i < perm.size(); ++i)
    {
        this->pb.val(sorted_u_[ perm[i] ]) = this->pb.val(u_[i]);
        this->pb.val(perm_v_[ perm[i] ])= this->pb.val(v_[i]);
    }

    for(size_t i=0; i < M+N-1; ++i)
        this->pb.val(delta_[i]) = this->pb.val(sorted_u_[i+1]) - this->pb.val(sorted_u_[i]);
    
}

} // end of namespace


#endif