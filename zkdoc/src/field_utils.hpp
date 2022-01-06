/** @file
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef ZKDOC_FIELD_UTILS_HPP_
#define ZKDOC_FIELD_UTILS_HPP_
#include <cstdint>

#include <libff/algebra/fields/bigint.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/fp.hpp>

namespace libff {

template<typename FieldT>
struct is_additive {
    static const bool value = false;
};


template<typename FieldT>
struct is_multiplicative {
    static const bool value = false;
};

template<mp_size_t n, const bigint<n>& modulus>
struct is_multiplicative<Fp_model<n, modulus>> {
    static const bool value = true;
};

enum field_type {
    multiplicative_field_type = 1,
    additive_field_type = 2
};

template<typename FieldT>
field_type get_field_type(const typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type elem);

template<typename FieldT>
field_type get_field_type(const typename enable_if<is_additive<FieldT>::value, FieldT>::type elem);


template<typename FieldT>
std::size_t log_of_field_size_helper(
    typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type field_elem);

template<typename FieldT>
std::size_t log_of_field_size_helper(
    typename enable_if<is_additive<FieldT>::value, FieldT>::type field_elem);

/*
template<typename FieldT>
std::size_t soundness_log_of_field_size_helper(
    typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type field_elem);

template<typename FieldT>
std::size_t soundness_log_of_field_size_helper(
    typename enable_if<is_additive<FieldT>::value, FieldT>::type field_elem);

template<typename FieldT>
std::size_t get_word_of_field_elem(
    typename enable_if<is_additive<FieldT>::value, FieldT>::type field_elem, size_t word);

template<typename FieldT>
std::size_t get_word_of_field_elem(
    typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type field_elem, size_t word);

template<typename FieldT>
FieldT coset_shift();

// returns root of unity of order n (for n a power of 2), if one exists
template<typename FieldT>
typename std::enable_if<std::is_same<FieldT, Double>::value, FieldT>::type
get_root_of_unity(const std::size_t n);

template<typename FieldT>
typename std::enable_if<!std::is_same<FieldT, Double>::value, FieldT>::type
get_root_of_unity(const std::size_t n);

template<typename FieldT>
std::vector<FieldT> pack_int_vector_into_field_element_vector(const std::vector<std::size_t> &v, const std::size_t w);

template<typename FieldT>
std::vector<FieldT> pack_bit_vector_into_field_element_vector(const bit_vector &v, const std::size_t chunk_bits);

template<typename FieldT>
std::vector<FieldT> pack_bit_vector_into_field_element_vector(const bit_vector &v);

template<typename FieldT>
std::vector<FieldT> convert_bit_vector_to_field_element_vector(const bit_vector &v);

template<typename FieldT>
bit_vector convert_field_element_vector_to_bit_vector(const std::vector<FieldT> &v);

template<typename FieldT>
bit_vector convert_field_element_to_bit_vector(const FieldT &el);

template<typename FieldT>
bit_vector convert_field_element_to_bit_vector(const FieldT &el, const std::size_t bitcount);

template<typename FieldT>
FieldT convert_bit_vector_to_field_element(const bit_vector &v);

template<typename FieldT>
void batch_invert(std::vector<FieldT> &vec);
*/
} // namespace libff
#include <zkdoc/src/field_utils.tcc>

#endif // FIELD_UTILS_HPP_
