#ifndef __TRUSTED_AI_NIZK__
#define __TRUSTED_AI_NIZK__

// include libsnark headers
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

// includes for definition of groups and fields
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <zkdoc/src/hashing/blake2b.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>

// include dependent headers
#include <zkdoc/src/trusted_ai_interactive_gadgets.hpp>
#include <zkdoc/src/adaptive-snark/trapdoor_commitment.hpp>
#include <zkdoc/src/adaptive-snark/r1cs_adaptive_snark.hpp>
#include <zkdoc/src/trusted_ai_cp_gadgets.hpp>

// include for hashing

#include <iostream>
#include <cassert>
#include <fstream>
#include <numeric>
#include <algorithm>
#include <random>
#include <tuple>


using namespace TrustedAI;
using namespace libsnark;
//using namespace libiop;


#define COMM_KEY_FILE "comm-key.txt"
#define PERM_KEY_PK "perm-key-pk.txt"
#define PERM_KEY_VK "perm-key-vk.txt"
#define ROM_KEY_PK "rom-key-pk.txt"
#define ROM_KEY_VK "rom-key-vk.txt"
#define ROM_PERM_KEY_PK "rom-perm-key-pk.txt"
#define ROM_PERM_KEY_VK "rom-perm-key-vk.txt"
#define FILTER_KEY_PK "filter-key-pk.txt"
#define FILTER_KEY_VK "filter-key-vk.txt"
#define AGGREGATE_KEY_PK "aggregate-key-pk.txt"
#define AGGREGATE_KEY_VK "aggregate-key-vk.txt"



// ****************************************************************************  //
// Overall NIZK strategy:                                                        //
// initialize hash state: hs                                                     //
// for each round:                                                               //
//   hs = hs.absorb(prover_message_for_round)                                    //
//   verifier_message = hs.squeeze(verifier_message_len)                         //
// ProverMessage:                                                                // 
//  Vector of knowledge commitments                                              // 
//  Vector of field elements                                                     //
//  Vector of G1 elements                                                        //
//  Vector of G2 elements                                                        //  
//  SNARK proof                                                                  //
//  toString() -- returns binary buffer corresponding to message                 //
//  ***************************************************************************  //


// Choose NIZK params
typedef libff::alt_bn128_pp snark_pp;
typedef libff::Fr<snark_pp> FieldT;
typedef knowledge_commitment<libff::G1<snark_pp>, libff::G2<snark_pp> > CommT;
typedef libff::G1<snark_pp> GType1;
typedef libff::G2<snark_pp> GType2;
typedef std::vector<std::vector<FieldT>> VecVecT;
typedef r1cs_adaptive_snark_proof<snark_pp> ProofT;
typedef libiop::blake2b_hashchain<FieldT, libiop::binary_hash_digest> HashChainT;


class ProverMessage;
typedef std::vector<ProverMessage> SnarkProof;

class ProverMessage
{
    public:
    std::vector<CommT> commVec;
    std::vector<FieldT> fieldVec;
    std::vector<GType1> groupVec1;
    std::vector<GType2> groupVec2;
    ProofT proof;
    bool containsProof;

    ProverMessage(): containsProof(false) {};

};

std::ostream& operator<<(std::ostream& out, const ProverMessage& msg)
{
    out << msg.commVec;
    out << msg.fieldVec;
    out << msg.groupVec1;
    out << msg.groupVec2;
    out << msg.proof;
    out << (msg.containsProof?1:0) << OUTPUT_NEWLINE;

    return out;
}

std::istream& operator>>(std::istream& in, ProverMessage& msg)
{
    size_t containsProof;
    in >> msg.commVec;
    in >> msg.fieldVec;
    in >> msg.groupVec1;
    in >> msg.groupVec2;
    in >> msg.proof;
    in >> containsProof;
    assert(containsProof == 0 || containsProof == 1);
    libff::consume_OUTPUT_NEWLINE(in);
    msg.containsProof = (containsProof == 1)?true:false;
    return in;
}

std::ostream& operator<<(std::ostream& out, const SnarkProof& snarkproof)
{
    out << snarkproof.size() << OUTPUT_NEWLINE;
    for(size_t i=0; i < snarkproof.size(); ++i)
    {
        out << snarkproof[i];        
    }

    return out;
}

std::istream& operator>>(std::istream& in, SnarkProof& snarkproof)
{
    snarkproof.clear();
    size_t nmesg;
    in >> nmesg;
    libff::consume_OUTPUT_NEWLINE(in);
    
    for(size_t i=0; i < nmesg; ++i)
    {
        ProverMessage msg;
        in >> msg;
        snarkproof.emplace_back(msg);
    }

    return in;
}

std::string toString(const ProverMessage& msg)
{
    std::stringstream str;
    str << msg;
    return str.str();
}


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

void log_message(const std::string& msg)
{
    std::cout << "[ " << __FUNCTION__ << " ]: " << msg << std::endl;
}

std::vector<CommT>
compute_comm_list(const commitment_key<snark_pp>& ck, const VecVecT& vec_list, const std::vector<FieldT>& rand_list)
{
    std::vector<CommT> comm_list;
    for(size_t i=0; i < vec_list.size(); ++i)
    {
        CommT comm = compute_commitment(ck, vec_list[i], rand_list[i]);
        comm_list.emplace_back(comm);
    }

    return comm_list;
}

CommT compute_linear_combination(const std::vector<FieldT>& coeffs, const std::vector<CommT>& comm_vec)
{
    CommT lc = CommT::zero();
    for(size_t i=0; i < coeffs.size(); ++i)
    {
        lc = lc + (coeffs[i] * comm_vec[i]);
    }

    return lc;
}

FieldT compute_linear_combination(const std::vector<FieldT>& coeffs, const std::vector<FieldT>& field_vec)
{
    FieldT lc = FieldT::zero();
    for(size_t i=0; i < coeffs.size(); ++i)
    {
        lc = lc + (coeffs[i] * field_vec[i]);
    }

    return lc;
}

std::vector<FieldT>
compute_linear_combination(const std::vector<FieldT>& coeffs, const VecVecT& field_mat)
{
    size_t n = field_mat.size();
    size_t m = field_mat[0].size();

    assert(coeffs.size() == n);
    std::vector<FieldT> lc(m, FieldT::zero());

    for(size_t i=0; i < coeffs.size(); ++i)
    {
        for(size_t j=0; j < m; ++j)
        {
            lc[j] = lc[j] + (coeffs[i] * field_mat[i][j]);
        }
    }

    return lc;
}

commitment_key<snark_pp>
read_commitment_key(const std::string& ckfilename)
{
    commitment_key<snark_pp> ck;
    std::ifstream ckfile(ckfilename);
    ck.deserialize(ckfile);
    ckfile.close();

    return ck;
}

r1cs_adaptive_snark_proving_key<snark_pp>
read_proving_key(const std::string& pkfilename)
{
    r1cs_adaptive_snark_proving_key<snark_pp> pk;
    std::ifstream pkfile(pkfilename);
    pkfile >> pk;
    pkfile.close();

    return pk;
}

r1cs_adaptive_snark_verification_key<snark_pp>
read_verification_key(const std::string& vkfilename)
{
    r1cs_adaptive_snark_verification_key<snark_pp> vk;
    std::ifstream vkfile(vkfilename);
    vkfile >> vk;
    vkfile.close();

    return vk;   
}


#endif