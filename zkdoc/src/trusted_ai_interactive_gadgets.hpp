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
    pb_variable_array<FieldT> less_, less_eq_;
    std::vector<comparison_gadget<FieldT>> compare_;
    //pb_variable_array<FieldT> diff_; 
    //std::vector<pb_variable_array<FieldT>> sorted_u_bits_;
    //std::vector<pb_variable_array<FieldT>> diff_bits_;   
    //std::vector<packing_gadget<FieldT>> pack_diff_;
    //std::vector<packing_gadget<FieldT>> pack_sorted_u_;
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

    size_t W = libff::log2(N);

    //diff_.allocate(this->pb, M+N-1, "diff");

    //sorted_u_bits_.resize(M+N);
    //for(size_t i=0; i < sorted_u_bits_.size(); ++i) 
    //    sorted_u_bits_[i].allocate(this->pb, W, "sorted_u_bits");
    
    //diff_bits_.resize(M+N-1);
    //for(size_t i=0; i < diff_bits_.size(); ++i)
    //    diff_bits_[i].allocate(this->pb, W, "diff_bits");

    //for(size_t i=0; i < sorted_u_.size(); ++i)
    //{
    //    pack_sorted_u_.emplace_back(
    //        packing_gadget<FieldT>(this->pb, sorted_u_bits_[i], sorted_u_[i], "pack sorted bits")
    //    );
    //}

    //for(size_t i=0; i < diff_.size(); ++i)
    //{
    //    pack_diff_.emplace_back(
    //        packing_gadget<FieldT>(this->pb, diff_bits_[i], diff_[i], "pack diff")
    //    );
    less_.allocate(this->pb, sorted_u_.size() - 1, "less");
    less_eq_.allocate(this->pb, sorted_u_.size() - 1, "less_eq");
    for(size_t i=0; i < less_.size(); ++i)
    {
        compare_.emplace_back(
            comparison_gadget<FieldT>(
                this->pb,
                W,
                sorted_u_[i+1],
                sorted_u_[i],
                less_[i],
                less_eq_[i],
                "comparison"
            )
        );
    }

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

    //for(size_t i=0; i < M+N-1; ++i)
    //{
    //    this->pb.add_r1cs_constraint(
    //        r1cs_constraint<FieldT>(
    //            diff_[i] + sorted_u_[i],
    //            1,
    //            sorted_u_[i+1]
    //        ), "diff constraint"
    //    );

    //}

    //for(size_t i=0; i < M+N; ++i)
    //    pack_sorted_u_[i].generate_r1cs_constraints(true);
    
    //for(size_t i=0; i < M+N-1; ++i)
    //    pack_diff_[i].generate_r1cs_constraints(true);

    for(size_t i=0; i < compare_.size(); ++i)
        compare_[i].generate_r1cs_constraints();

    std::vector<FieldT> coefficients(less_.size(), FieldT::one());
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(pb_coeff_sum(pb_linear_combination_array<FieldT>(less_), coefficients), 1, 0),
        "sorted order"
    );

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

    //for(size_t i=0; i < M+N-1; ++i)
    //        this->pb.val(diff_[i]) = this->pb.val(sorted_u_[i+1]) - this->pb.val(sorted_u_[i]);

    //for(size_t i=0; i < M+N; ++i)
    //    pack_sorted_u_[i].generate_r1cs_witness_from_packed();
    
    //for(size_t i=0; i < M+N-1; ++i)
    //    pack_diff_[i].generate_r1cs_witness_from_packed();

    for(size_t i=0; i < compare_.size(); ++i)
        compare_[i].generate_r1cs_witness();
    
}


} // end of namespace


#endif