#ifndef __TRUSTED_AI_UTILITY_GADGETS__
#define __TRUSTED_AI_UTILITY_GADGETS__

#include <libfqfft/polynomial_arithmetic/basic_operations.hpp>
#include <libfqfft/polynomial_arithmetic/naive_evaluate.hpp>

using namespace libsnark;
using namespace libfqfft;

namespace TrustedAI {

std::vector<size_t>
find_permutation_for_sort(
    const std::vector<size_t>& unsorted,
    const std::vector<size_t>& sorted
)
{
    assert(sorted.size() == unsorted.size());
    /**
     * We will do a simple brain-dead algorithm here
     * for each element on unsorted, we look up the 
     * first free index on the right hand side
     * Takes O(size^2) time, but that's not what will kill us here :)
     */

    std::vector<size_t> free_indices(sorted.size(), 0);
    std::vector<size_t> perm(sorted.size(), 0);

    for(size_t i=0; i < unsorted.size(); ++i)
    {
        size_t j=0;
        while ((j < sorted.size()) && 
            !(free_indices[j] == 0 && sorted[j] == unsorted[i])) j++;
        
        assert(j != sorted.size());
        perm[i] = j;
        free_indices[j] = 1;
    }

    return perm;
}

/**
 * The function takes in a sorted array, and returns two arrays:
 * The second argument is passed by reference and is populated with
 * permutation of sorted array with unique elements first.
 * The corresponding permutation between the two is returned as return value
 */
std::vector<size_t>
find_permutation_for_unique(
    const std::vector<size_t>& sorted,
    std::vector<size_t>& unique_first
)
{
    unique_first.resize(sorted.size());
    std::vector<size_t> perm(sorted.size());
    
    size_t i=0;
    size_t j=sorted.size();
    unique_first[0] = sorted[0];
    
    for(size_t k=1; k < sorted.size(); ++k)
    {
        if (sorted[k] == unique_first[i]) {
            // this is a repeated element
            unique_first[j-1] = sorted[k];
            perm[k] = j-1;
            j--;
        } else {
            unique_first[i+1] = sorted[k];
            perm[k] = i+1;
            i++;
        }
    }

    return perm;
}


/**
 * Compute lagrangian basis
 * 
 */
template<typename FieldT>
std::vector<std::vector<FieldT>> compute_lagrange_polynomials(size_t n)
{
    std::vector<std::vector<FieldT>> basis_polynomials(n);
    std::vector<std::vector<FieldT>> monomials(n);
    std::vector<FieldT> coefficients; // polynomials of length 1

    std::vector<FieldT> product_polynomial(1, FieldT::one());
    for(size_t i=0; i < n; ++i) {
        std::vector<FieldT> monomial;
        std::vector<FieldT> current_product = product_polynomial;
        monomial.emplace_back(FieldT::zero() - FieldT(i));
        monomial.emplace_back(FieldT::one());
        _polynomial_multiplication(product_polynomial, current_product, monomial);
    }

    for(size_t i=0; i < n; ++i) {
        std::vector<FieldT> monomial;
        monomial.emplace_back(FieldT::zero() - FieldT(i));
        monomial.emplace_back(FieldT::one());
        std::vector<FieldT> q, r;
        _polynomial_division(basis_polynomials[i], r, product_polynomial, monomial);
    }

    for(size_t i=0; i < n; ++i)
    {
        FieldT t(i);
        coefficients.emplace_back(evaluate_polynomial<FieldT>(basis_polynomials[i].size(), basis_polynomials[i], t).inverse());
    }

    // scale the basis polynomials
    for(size_t i=0; i < basis_polynomials.size(); ++i) {
        for(size_t j=0; j < basis_polynomials[i].size(); ++j) 
            basis_polynomials[i][j] = coefficients[i] * basis_polynomials[i][j];
    }

    return basis_polynomials;
}


/**
 * Interpolate polynomial p(x)\in F[x] such that p(i) = v[i]
 * 
 */
template<typename FieldT>
std::vector<FieldT> interpolate_polynomial(const std::vector<uint64_t>& v, const std::vector<std::vector<FieldT>>& basis_polynomials)
{

    // initial value of interpolation polynomial
    std::vector<FieldT> interpolation_polynomial(1, FieldT::zero());

    for(size_t i=0; i < v.size(); ++i)
    {
        auto current_polynomial = interpolation_polynomial;
        auto lagrange_term = basis_polynomials[i];
        // scale the lagrange term by the v coefficient
        for(size_t j=0; j < lagrange_term.size(); ++j) {
            lagrange_term[j] = FieldT(v[i]) * lagrange_term[j];
        }

        _polynomial_addition(interpolation_polynomial, current_polynomial, lagrange_term);
    }

    return interpolation_polynomial;
}

template<typename FieldT>
class size_enforcing_gadget : public gadget<FieldT> {
public:
    // variable to denote size
    size_t max_size_; 
    pb_variable<FieldT> vsize_;
    pb_variable_array<FieldT> selector_;
    
private:
    // auxiliary variables to link vsize_ to selector_
    // see generate_r1cs_constraints() for details.
    pb_variable_array<FieldT> reverse_;
    pb_variable_array<FieldT> z_;
    pb_variable_array<FieldT> w_;

public:
    size_enforcing_gadget(
        protoboard<FieldT>& pb,
        size_t max_size,
        const pb_variable<FieldT>& vsize,
        const pb_variable_array<FieldT>& selector,
        const std::string& annotation_prefix = "") : 
            gadget<FieldT>(pb, annotation_prefix), 
            max_size_(max_size), vsize_(vsize), selector_(selector) {};

    std::vector<pb_variable<FieldT> > get_pb_vals() { 
        std::vector<pb_variable<FieldT> > pb_vals;
        std::copy(selector_.begin(), selector_.end(), back_inserter(pb_vals));
        return pb_vals;
    };

    // allocates the auxiliary witness
    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
void size_enforcing_gadget<FieldT>::allocate()
{
    // we assume that input and output to the gadget
    // namely vsize_ and selector_ are added to the
    // protoboard by the caller. Here we add the auxiliary 
    // inputs to the protoboard
    this->reverse_.allocate(this->pb, max_size_, this->annotation_prefix);
    this->z_.allocate(this->pb, max_size_, this->annotation_prefix);
    this->w_.allocate(this->pb, max_size_, this->annotation_prefix);
}

template<typename FieldT>
void size_enforcing_gadget<FieldT>::generate_r1cs_constraints()
{

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(vsize_ - reverse_[0], 1, FieldT::zero()),
        this->annotation_prefix);  // (1)

    for(size_t i=1; i < max_size_; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(reverse_[i-1] - 1, selector_[i-1], reverse_[i]), "reverse[i]=selector[i-1]*(reverse[i-1]-1)"); // (2)
    }
   

    for(size_t i=0; i < max_size_; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(z_[i], selector_[i], reverse_[i]),
            "z[i]*selector[i]=reverse[i]"); // (4)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(z_[i], w_[i], 1),
            "z[i]*w[i]=1"); // (3)
    }

    for(size_t i=0; i < max_size_; ++i)
        generate_boolean_r1cs_constraint<FieldT>(this->pb, selector_[i], this->annotation_prefix); // (5)
    
}

template<typename FieldT>
void size_enforcing_gadget<FieldT>::generate_r1cs_witness()
{
    // We assume that vsize is already set (as input)
    size_t size = this->pb.val(this->vsize_).as_ulong();

    for(size_t i=0; i < size; ++i) {
        this->pb.val(reverse_[i]) = size - i;
        this->pb.val(z_[i]) = size - i;
        this->pb.val(w_[i]) = this->pb.val(z_[i]).inverse();
        this->pb.val(selector_[i]) = 1;
    }

    for(size_t i=size; i < max_size_; ++i) {
        this->pb.val(reverse_[i]) = 0;
        this->pb.val(selector_[i]) = 0;
        this->pb.val(z_[i]) = 1;
        this->pb.val(w_[i]) = 1;
    }

}

template<typename FieldT>
class polynomial_evaluation_gadget : public gadget<FieldT>
{
    public:
    polynomial_evaluation_gadget(
        protoboard<FieldT>& pb,
        pb_variable_array<FieldT>& poly,
        pb_variable<FieldT>& point,
        pb_variable<FieldT>& value,
        const std::string& annotation_prefix=""
    );

    void allocate() {};

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    private:
    pb_variable<FieldT> point_, value_;
    pb_variable_array<FieldT> poly_;

    // auxiliary values
    pb_variable_array<FieldT> partial_;
};


template<typename FieldT>
polynomial_evaluation_gadget<FieldT>::polynomial_evaluation_gadget(
    protoboard<FieldT>& pb,
    pb_variable_array<FieldT>& poly,
    pb_variable<FieldT>& point,
    pb_variable<FieldT>& value,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    poly_(poly),
    point_(point),
    value_(value)
{
    size_t n = poly_.size();
    assert(n >= 1);
    if (n > 2)    
        partial_.allocate(this->pb, n-2, "intermediate evaluations");
    
}

template<typename FieldT>
void polynomial_evaluation_gadget<FieldT>::generate_r1cs_constraints()
{
    size_t n = poly_.size();
    if (n == 1) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(poly_[0], 1, value_), 
            "p[0]=value"
        );
    } else if (n == 2) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(point_, poly_[1], value_ - poly_[0]), 
            "value=p[1].point + p[0]"
        );
    } else {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(point_, poly_[n-1], partial_[0] - poly_[n-2]),
            "boundary constraint 1"
        );

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(point_, partial_[n-3], value_ - poly_[0]),
            "boundary constraint 2"
        );

        for(size_t i=1; i < n-2; ++i) {
           this->pb.add_r1cs_constraint(
               r1cs_constraint<FieldT>(point_, partial_[i-1], partial_[i] - poly_[n-2-i]), "intermediate value computation"
           );     
        }
    }
}

template<typename FieldT>
void polynomial_evaluation_gadget<FieldT>::generate_r1cs_witness()
{
    size_t n = poly_.size();
    if (n > 2) {
        this->pb.val(partial_[0]) = this->pb.val(point_) * this->pb.val(poly_[n-1]) + this->pb.val(poly_[n-2]);
        for(size_t i=1; i < n-2; ++i) {
            this->pb.val(partial_[i]) = this->pb.val(point_)*this->pb.val(partial_[i-1]) + this->pb.val(poly_[n-2-i]);
        }

        this->pb.val(value_) = this->pb.val(point_) * this->pb.val(partial_[n-3]) + this->pb.val(poly_[0]); 
    }

}

template<typename FieldT>
class cumulative_sum_gadget : public gadget<FieldT> 
{
    private:
    pb_variable_array<FieldT> vec_, cusum_vec_;


    public:
    cumulative_sum_gadget(
        protoboard<FieldT>& pb,
        pb_variable_array<FieldT>& vec,
        pb_variable_array<FieldT>& cusum_vec,
        const std::string& annotation_prefix=""
    ): gadget<FieldT>(pb, annotation_prefix),
    vec_(vec), cusum_vec_(cusum_vec) {};

    void allocate() {};

    void generate_r1cs_constraints() {
        assert(vec_.size() == cusum_vec_.size());
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vec_[0],
                1,
                cusum_vec_[0]
            ), "cusum_vec[0]=vec[0]"
        );

        for(size_t i=1; i < vec_.size(); ++i)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    vec_[i] + cusum_vec_[i-1],
                    1,
                    cusum_vec_[i]
                ), "cusum_vec[i]=cusum_vec[i-1]+vec[i]"
            );
    };

    void generate_r1cs_witness() {
        assert(vec_.size() == cusum_vec_.size());
        this->pb.val(cusum_vec_[0]) = this->pb.val(vec_[0]);

        for(size_t i=1; i < vec_.size(); ++i)
            this->pb.val(cusum_vec_[i]) = this->pb.val(cusum_vec_[i-1]) + this->pb.val(vec_[i]);

    };
};

template<typename FieldT>
class lock_step_gadget : public gadget<FieldT>
{

    private:
    pb_variable_array<FieldT> A_, B_;
    // auxiliary input
    pb_variable_array<FieldT> x_;

    public:
    lock_step_gadget(
        protoboard<FieldT>& pb,
        pb_variable_array<FieldT>& A,
        pb_variable_array<FieldT>& B,
        const std::string& annotation_prefix = ""):
        gadget<FieldT>(pb, annotation_prefix),
        A_(A),
        B_(B) 
        {
            x_.allocate(this->pb, A_.size() - 1, "x_");
        };

    void allocate() {};

    void generate_r1cs_constraints()
    {
        assert(A_.size() == B_.size());

        for(size_t i=1; i < A_.size(); ++i) 
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    A_[i] - A_[i-1],
                    x_[i-1],
                    B_[i] - B_[i-1]
                ), "step-sync-constraint"
            );
        
    };

    void generate_r1cs_witness()
    {
        for(size_t i=1; i < A_.size(); ++i) {
            if (this->pb.val(A_[i]) == this->pb.val(A_[i-1])) {
                this->pb.val(x_[i-1]) = 0;
            } else {
            this->pb.val(x_[i-1]) = (this->pb.val(B_[i]) - this->pb.val(B_[i-1])) * 
                (this->pb.val(A_[i]) - this->pb.val(A_[i-1])).inverse();
            }
        }

    };

};

template<typename FieldT>
class hadamard_product_gadget : public gadget<FieldT> 
{
    private:
    pb_variable_array<FieldT> x_, y_, z_;

    public:
    hadamard_product_gadget(
        protoboard<FieldT>& pb,
        pb_variable_array<FieldT>& x,
        pb_variable_array<FieldT>& y,
        pb_variable_array<FieldT>& z,
        const std::string& annotation_prefix=""
    ): gadget<FieldT>(pb, annotation_prefix),
    x_(x), y_(y), z_(z) 
    {};

    void allocate() {};

    void generate_r1cs_constraints()
    {
        for(size_t i=0; i < x_.size(); ++i)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(x_[i], y_[i], z_[i]),
                "hadamard_product"
            );


    };

    void generate_r1cs_witness()
    {
        for(size_t i=0; i < x_.size(); ++i)
            this->pb.val(z_[i]) = this->pb.val(x_[i]) * this->pb.val(y_[i]);

    };
    
};

} // end of namespace
#endif