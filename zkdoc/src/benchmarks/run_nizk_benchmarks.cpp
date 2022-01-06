#include <zkdoc/src/trusted_ai_simultaneous_permutation_snark.hpp>
#include <zkdoc/src/trusted_ai_rom_access_snark.hpp>
#include <zkdoc/src/trusted_ai_filter_snark.hpp>

unsigned int get_random_value(size_t n)
{
    std::random_device rd;  // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> distrib(0, n-1);
    return distrib(gen);
}



// example for filter protocol
struct filter_example_type {
    unsigned int size;
    std::vector<size_t> source;
    std::vector<size_t> f;
    std::vector<size_t> target;
};

// generate an example for filter protocol
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



void test_simultaneous_permutation_snark()
{
    snark_pp::init_public_params();
    HashChainT hash_chain(80);

    size_t slot_size = 100000;
    size_t N = 100000;
    std::vector<FieldT> X, Y;

    for(size_t i=0; i < N; ++i)
    {
        FieldT r = FieldT::random_element();
        X.emplace_back(r);
        Y.emplace_back(r);
    }

    std::random_shuffle(Y.begin(), Y.end());

    VecVecT left(1), right(1);
    left[0]=X;
    right[0]=Y;

    std::vector<FieldT> rand_left, rand_right;
    rand_left.emplace_back(FieldT::random_element());
    rand_right.emplace_back(FieldT::random_element());

    SnarkProof snarkproof = simultaneous_permutation_snark_prover(
        PERM_KEY_PK, 
        hash_chain,
        slot_size, 
        left, 
        right, 
        rand_left, 
        rand_right);

    {   // write proof block
        std::ofstream pfile("snarkproof.txt");
        pfile << snarkproof;
        pfile.close();
    }

    {   // read and verify proof
        SnarkProof proof;
        HashChainT hash_chain(80);
        std::ifstream pfile("snarkproof.txt");
        pfile >> proof;
        bool result = simultaneous_permutation_snark_verifier(PERM_KEY_VK, hash_chain, slot_size, proof);
    }

}

void test_rom_access_snark()
{
    snark_pp::init_public_params();
    HashChainT hash_chain(80);

    size_t slot_size = 200000;
    size_t N = 100000;
    size_t M = 100000;

    // generate vectors L, U and V
    std::vector<FieldT> L(N), U(M), V(M);

    for(size_t i=0; i < N; ++i)
        L[i] = FieldT::random_element();

    for(size_t i=0; i < M; ++i)
    {
        U[i] = (i % N);
        V[i] = L[ i % N ];
    }

    MemInfoT mem_info;
    AccessInfoT access_info;
    ValueInfoT val_info;

    mem_info.mem_list.emplace_back(L);
    mem_info.rand_mem_list.emplace_back(FieldT::random_element());

    access_info.read_locations = U;
    access_info.rand_read_locations = FieldT::random_element();

    val_info.values_list.emplace_back(V);
    val_info.rand_values_list.emplace_back(FieldT::random_element());

    SnarkProof proof = multiplexed_rom_access_prover(ROM_KEY_PK, hash_chain, slot_size, mem_info, access_info, val_info);
    std::ofstream outfile("snark-proof-rom.txt");
    outfile << proof;
    outfile.close();
    {
        SnarkProof proof;
        std::ifstream infile("snark-proof-rom.txt");
        infile >> proof;
        
        HashChainT hash_chain(80);
        bool ret = multiplexed_rom_access_verifier(ROM_KEY_VK, hash_chain, slot_size, proof);
        if (ret) {
            log_message("Proof Verified Successfully");
        } else
            log_message("Proof Verification Failed");
    }

}

void test_filter_dataset_snark()
{
    snark_pp::init_public_params();

    size_t max_rows = 100000;

    VecVecT source = {
        {5, 1, 2, 3, 4, 5},
        {5, 2, 4, 6, 8, 10}
    };

    VecVecT dest = {
        {2, 1, 5},
        {2, 2, 10}
    };

    std::vector<FieldT> f = {1, 0, 0, 0, 1};
    std::vector<FieldT> rand_source, rand_dest;
    rand_source.emplace_back(FieldT::random_element());
    rand_source.emplace_back(FieldT::random_element());
    rand_dest.emplace_back(FieldT::random_element());
    rand_dest.emplace_back(FieldT::random_element());
    auto rand_f = FieldT::random_element();

    // resize the vectors
    for(size_t i=0; i < source.size(); ++i)
    {
        source[i].resize(1 + max_rows, FieldT::zero());
        dest[i].resize(1 + max_rows, FieldT::zero());
    }    

    f.resize(max_rows, FieldT::zero());

    DatasetT dA = {source, rand_source};
    DatasetT dB = {dest, rand_dest};
    VectorT fvec = {f, rand_f};

    // initialize hash chain
    HashChainT hash_chain(80);

    SnarkProof snarkproof = filter_dataset_prover(
        FILTER_KEY_PK,
        hash_chain,
        1 + max_rows,
        dA,
        fvec,
        dB
    );

    // verify proof
    bool ret;

    {
        HashChainT hash_chain(80);
        ret = filter_dataset_verifier(
            FILTER_KEY_VK,
            hash_chain,
            1 + max_rows,
            snarkproof
        );
    }

    if (ret)
        log_message("Filter Proof Verification Succeeded");
    else
        log_message("Filter Proof Verification failed");

}

void test_aggregate_dataset_snark()
{
    snark_pp::init_public_params();

    size_t max_rows = 100000;

    VecVecT sourceA = {
        {5, 1, 2, 3, 4, 5},
        {5, 2, 4, 6, 8, 10}
    };

    VecVecT sourceB = {
        {3, 6, 7, 8},
        {3, 12, 14, 16}
    };

    VecVecT dest = {
        {8, 1, 2, 3, 4, 5, 6, 7, 8},
        {8, 2, 4, 6, 8, 10, 12, 14, 16}
    };

    std::vector<FieldT> rand_sourceA, rand_sourceB, rand_dest;
    rand_sourceA.emplace_back(FieldT::random_element());
    rand_sourceA.emplace_back(FieldT::random_element());
    rand_sourceB.emplace_back(FieldT::random_element());
    rand_sourceB.emplace_back(FieldT::random_element());
    rand_dest.emplace_back(FieldT::random_element());
    rand_dest.emplace_back(FieldT::random_element());

    // resize the vectors
    for(size_t i=0; i < sourceA.size(); ++i)
    {
        sourceA[i].resize(1 + max_rows, FieldT::zero());
        sourceB[i].resize(1 + max_rows, FieldT::zero());
        dest[i].resize(1 + max_rows, FieldT::zero());
    }    


    DatasetT dA = {sourceA, rand_sourceA};
    DatasetT dB = {sourceB, rand_sourceB};
    DatasetT dC = {dest, rand_dest};

    // initialize hash chain
    HashChainT hash_chain(80);

    SnarkProof snarkproof = aggregate_dataset_prover(
        AGGREGATE_KEY_PK,
        hash_chain,
        2*max_rows,
        dA,
        dB,
        dC
    );

    // verify proof
    bool ret;

    {
        HashChainT hash_chain(80);
        ret = aggregate_dataset_verifier(
            AGGREGATE_KEY_VK,
            hash_chain,
            2*max_rows,
            snarkproof
        );
    }

    if (ret)
        log_message("Aggregation Proof Verification Succeeded");
    else
        log_message("Aggregation Proof Verification failed");

}



int main(int argc, char *argv[])
{
    //test_simultaneous_permutation_snark();
    // test_rom_access_snark();
    //test_filter_dataset_snark();
    test_aggregate_dataset_snark();
    return 0;
}
