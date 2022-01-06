#include <zkdoc/src/trusted_ai_nizk.hpp>
#include <zkdoc/src/trusted_ai_simultaneous_permutation_snark.hpp>
#include <zkdoc/src/trusted_ai_rom_access_snark.hpp>
#include <zkdoc/src/trusted_ai_filter_snark.hpp>
#include <zkdoc/src/dataset-representation.hpp>

#include <zkdoc/src/httplib.h>
#include <zkdoc/src/json.hpp>

using namespace httplib;
using json = nlohmann::json;

commitment_key<snark_pp> ck;

namespace systemparams {
    const size_t max_data_size = 100000;
    const size_t security_bits_hash = 80;

};


void generateHash(const Request& req, Response& res)
{
    if (req.has_param("document-plaintext"))
    {
        auto val = req.get_param_value("document-plaintext");
        std::cout << val << std::endl;
        auto columns = json::parse(val);
        // res.set_content(columns.dump(4), "application/json");
        auto doc = parse_json_as_document(columns);
        std::cout << "Received " << doc.size() << "cols, " << doc[0].size() << " rows" << std::endl;

        VecVecT doc_over_FF = get_document_over_field(doc, 1 + systemparams::max_data_size);
        std::cout <<  doc_over_FF.size();

        std::vector<CommT> comms = compute_comm_list(ck, doc_over_FF, std::vector<FieldT>(doc_over_FF.size(), FieldT::zero()));

        // build response json
        json jcomms = json::array();

        for(size_t i=0; i < comms.size(); ++i)
        {
            std::stringstream str;
            str << comms[i];
            json jcomm(str.str());
            jcomms.push_back(jcomm);
        } 

        res.set_content(jcomms.dump(4), "text/plain");      

    }

}

void proveaggregate(const Request& req, Response& res)
{
    auto docA_str = req.get_param_value("data-source-A");
    auto docB_str = req.get_param_value("data-source-B");
    auto docC_str = req.get_param_value("data-dest-C");

    auto docA = parse_json_as_document(json::parse(docA_str));
    auto docB = parse_json_as_document(json::parse(docB_str));
    auto docC = parse_json_as_document(json::parse(docC_str));

    // get vectors over field 

    if ((docA.size() != docB.size()) || (docA.size() != docC.size()))
    {
        res.status = -1;
        return;
    }

    auto dataA = get_document_over_field(docA, 1 + systemparams::max_data_size);
    auto dataB = get_document_over_field(docB, 1 + systemparams::max_data_size);
    auto dataC = get_document_over_field(docC, 1 + systemparams::max_data_size);

    DatasetT dA = {dataA, std::vector<FieldT>(dataA.size())};
    DatasetT dB = {dataB, std::vector<FieldT>(dataB.size())};
    DatasetT dC = {dataC, std::vector<FieldT>(dataC.size())};

    SnarkProof proof;
    // initialize hash chain
    HashChainT hash_chain(systemparams::security_bits_hash);

    SnarkProof snarkproof = aggregate_dataset_prover(
        AGGREGATE_KEY_PK,
        hash_chain,
        2*systemparams::max_data_size,
        dA,
        dB,
        dC
    );

    std::stringstream proofstr;
    proofstr << snarkproof;

    json j;
    j["proof"] = proofstr.str();
    res.set_content(j.dump(4), "text/plain");
}

void verifyaggregate(const Request& req, Response& res)
{
    bool status = false;

    auto hashA_str = req.get_param_value("hash-source-A");
    auto hashB_str = req.get_param_value("hash-source-B");
    auto hashC_str = req.get_param_value("hash-dest-C");
    auto proof_str = req.get_param_value("proof");

    std::cerr << "finished reading request params" << std::endl;

    std::vector<CommT> cmA, cmB, cmC;

    cmA = get_comm_list_from_json(hashA_str);
    cmB = get_comm_list_from_json(hashB_str);
    cmC = get_comm_list_from_json(hashC_str);

    SnarkProof snarkproof;
    std::istringstream proof_stream(proof_str);
    proof_stream >> snarkproof;

    auto cmVec = cmA;
    cmVec.insert(cmVec.end(), cmB.begin(), cmB.end());
    cmVec.insert(cmVec.end(), cmC.begin(), cmC.end());

    if (snarkproof[0].commVec == cmVec)
    {
        HashChainT hash_chain(systemparams::security_bits_hash);
        status = aggregate_dataset_verifier(
            AGGREGATE_KEY_VK,
            hash_chain,
            2*systemparams::max_data_size,
            snarkproof
        );
    } 

    json j;
    j["verification-status"] = status;
    res.set_content(j.dump(4), "text/plain");
}

int main(int argc, char *argv[])
{
    snark_pp::init_public_params();

    ck = read_commitment_key(COMM_KEY_FILE);
    
    Server svr;

    svr.Get("/test/status", [](const Request& req, Response& res) {
        res.set_content("OK!", "text/plain");
    });
    
    svr.Post("/test/genhash", [](const Request& req, Response& res) {
        generateHash(req, res);

    });

    svr.Post("/test/proveaggregate", [](const Request& req, Response& res) {
        proveaggregate(req, res);
    });

    svr.Post("/test/verifyaggregate", [](const Request& req, Response& res) {
        verifyaggregate(req, res);
    });

    svr.set_payload_max_length(1024 * 1024 * 10);
    svr.listen("127.0.0.1", 5000);
}
