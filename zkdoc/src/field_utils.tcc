/** @file
 *****************************************************************************
 Implementation of misc. math and serialization utility functions
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef ZKDOC_FIELD_UTILS_TCC_
#define ZKDOC_FIELD_UTILS_TCC_

#include <complex>
#include <stdexcept>

namespace libff {

using std::size_t;

template<typename FieldT>
field_type get_field_type(const typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type elem)
{
    UNUSED(elem); // only to identify field type
    return multiplicative_field_type;
}

template<typename FieldT>
field_type get_field_type(const typename enable_if<is_additive<FieldT>::value, FieldT>::type elem)
{
    UNUSED(elem); // only to identify field type
    return additive_field_type;
}

template<typename FieldT>
std::size_t log_of_field_size_helper(
    typename enable_if<is_multiplicative<FieldT>::value, FieldT>::type field_elem)
{
    UNUSED(field_elem);
    return FieldT::ceil_size_in_bits();
}

template<typename FieldT>
std::size_t log_of_field_size_helper(
    typename enable_if<is_additive<FieldT>::value, FieldT>::type field_elem)
{
    UNUSED(field_elem);
    return FieldT::extension_degree();
}

} // namespace libff

#endif