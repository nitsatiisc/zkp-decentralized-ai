#ifndef __TRUSTED_AI_MIMC_CIPHER__
#define __TRUSTED_AI_MIMC_CIPHER__

using namespace libsnark;

namespace TrustedAI {

template<typename FieldT>
class mimc_cipher : public gadget<FieldT> {
public:
    static const size_t ROUNDS = 64;
    pb_variable<FieldT> input_, key_, hash_;
    std::vector<FieldT> round_constants_ {
		42,
		43,
		170,
		2209,
		16426,
		78087,
		279978,
		823517,
		2097194,
		4782931,
		10000042,
		19487209,
		35831850,
		62748495,
		105413546,
		170859333,
		268435498,
		410338651,
		612220074,
		893871697,
		1280000042,
		1801088567,
		2494357930,
		3404825421,
		4586471466,
		6103515587,
		8031810218,
		10460353177,
		13492928554,
		17249876351,
		21870000042,
		27512614133,
		34359738410,
		42618442955,
		52523350186,
		64339296833,
		78364164138,
		94931877159,
		114415582634,
		137231006717,
		163840000042,
		194754273907,
		230539333290,
		271818611081,
		319277809706,
		373669453167,
		435817657258,
		506623120485,
		587068342314,
		678223072891,
		781250000042,
		897410677873,
		1028071702570,
		1174711139799,
		1338925210026,
		1522435234413,
		1727094849578,
		1954897493219,
		2207984167594,
		2488651484857,
		2799360000042,
		3142742835999,
		3521614606250,
		3938980639125
    };

private:
    pb_variable_array<FieldT> intermediate_inputs_;
    pb_variable_array<FieldT> intermediate_lc2_;
    pb_variable_array<FieldT> intermediate_lc4_;
    pb_variable_array<FieldT> intermediate_lc6_;
    
public:
    mimc_cipher(
        protoboard<FieldT>& pb,
        const pb_variable<FieldT>& input,
        const pb_variable<FieldT>& key,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix);
    
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

}; // end of class definition mimc_cipher

template<typename FieldT>
mimc_cipher<FieldT>::mimc_cipher(
    protoboard<FieldT>& pb,
    const pb_variable<FieldT>& input,
    const pb_variable<FieldT>& key,
    const pb_variable<FieldT>& hash,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    input_(input), key_(key), hash_(hash)
{
    //input[i] ----> ROUND(i) -----> input[i+1]
    intermediate_inputs_.allocate(this->pb, ROUNDS+1, "intermediate_inputs");
    intermediate_lc2_.allocate(this->pb, ROUNDS, "intermediate_lc2");
    intermediate_lc4_.allocate(this->pb, ROUNDS, "intermediate_lc4");
    intermediate_lc6_.allocate(this->pb, ROUNDS, "intermediate_lc6");

}


template<typename FieldT>
void mimc_cipher<FieldT>::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            intermediate_inputs_[0],
            1,
            input_), "intermediate_[0] = input[0]");

    for(size_t i=0; i < ROUNDS; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_lc2_[i]), "a=input+key+rc");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_lc2_[i],
                intermediate_lc2_[i],
                intermediate_lc4_[i]), "a4 = a2*a2");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_lc4_[i],
                intermediate_lc2_[i],
                intermediate_lc6_[i]), "a6=a4*a2");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_lc6_[i],
                intermediate_inputs_[i+1]), "input[i+1]=f(input[i])");
    }

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            intermediate_inputs_[ROUNDS] + key_,
            1,
            hash_), "hash_ = final_input + key");
}

template<typename FieldT>
void mimc_cipher<FieldT>::generate_r1cs_witness()
{
    this->pb.val(intermediate_inputs_[0]) = this->pb.val(input_);
    for(size_t i=0; i < ROUNDS; ++i) {
        pb_linear_combination<FieldT> lc;
        lc.assign(this->pb, intermediate_inputs_[i] + key_ + round_constants_[i]);
        lc.evaluate(this->pb);
        this->pb.val(intermediate_lc2_[i]) = this->pb.lc_val(lc) * this->pb.lc_val(lc);
        this->pb.val(intermediate_lc4_[i]) = this->pb.val(intermediate_lc2_[i]) * this->pb.val(intermediate_lc2_[i]);
        this->pb.val(intermediate_lc6_[i]) = this->pb.val(intermediate_lc4_[i]) * this->pb.val(intermediate_lc2_[i]);
        this->pb.val(intermediate_inputs_[i+1]) = this->pb.lc_val(lc) * this->pb.val(intermediate_lc6_[i]);
    }
    
    this->pb.val(hash_) = this->pb.val(intermediate_inputs_[ROUNDS]) + this->pb.val(key_);
}

} // end of namespace

#endif
