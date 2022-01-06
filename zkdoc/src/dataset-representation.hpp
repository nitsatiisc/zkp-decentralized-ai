#ifndef __TRUSTED_AI_DATASET_REPRESENTATION__
#define __TRUSTED_AI_DATASET_REPRESENTATION__

#include <yaml-cpp/yaml.h>
#include <rapidcsv.h>
#include <zkdoc/src/json.hpp>

#include <memory>
#include <vector>
#include <map>

namespace TrustedAI {

using json = nlohmann::json;

/**
 * Utility functions for passing data, datahandles, proofs 
 * via rest calls
 */
std::vector<std::vector<int>> 
parse_json_as_document(const json& js)
{
    std::vector<std::vector<int>> doc;
    if (js.size() == 0) 
        return doc;

    size_t ncols = js.size();
    size_t nrows = js[0].size();

    doc.resize(ncols, std::vector<int>(nrows));
    
    for(size_t i=0; i < ncols; ++i)
    {
        for(size_t j=0; j < nrows; ++j)
        {
            doc[i][j] = std::stoi(js[i][j].get<std::string>());
        }
    }
    

    return doc;
}

std::vector<CommT>
get_comm_list_from_json(const std::string& json_str)
{
    std::vector<CommT> cm_list;
    json j = json::parse(json_str);

    for(size_t i=0; i < j.size(); ++i)
    {
        auto cm_str = j[i].get<std::string>();
        std::istringstream cm_stream(cm_str);
        CommT cm;
        cm_stream >> cm;
        cm_list.emplace_back(cm);
    }

    return cm_list;
}

/**
 * Utility to convert document into the form it is input to
 * verification circuits
 */
VecVecT get_document_over_field(const std::vector<std::vector<int>>& doc, size_t doc_size)
{
    VecVecT doc_over_FF(doc.size());
    for(size_t i=0; i < doc.size(); ++i)
    {
        doc_over_FF[i].emplace_back(doc[i].size());
        doc_over_FF[i].insert(doc_over_FF[i].end(), doc[i].begin(), doc[i].end());
        doc_over_FF[i].resize(doc_size, FieldT::zero());
    }


    return doc_over_FF;
}

class DataSet {

    private:
    std::shared_ptr<rapidcsv::Document> doc;
    std::vector<std::string> hashes;
    std::vector<std::string> columns;


    public:

    int read_data(const std::string& filename);

    int read_data_handle(const std::string& filename);

    size_t num_rows() { return doc->GetRowCount(); };

    size_t num_cols() { return doc->GetColumnCount(); };

    


    std::vector<std::string> get_column_as_string(size_t idx) { return doc->GetColumn<std::string>(idx); };

    std::vector<int> get_column_as_integer(size_t idx) { return doc->GetColumn<int>(idx); };

    std::string get_document_json();

    std::string get_datahandle_json();

};

int DataSet::read_data(const std::string& filename)
{
    int success = -1;
    try {
        doc.reset(new rapidcsv::Document(filename));
    } catch (std::exception& e)
    {
        std::cerr << "Error reading the data" << e.what() << std::endl;
        return success;
    }

    return 0;
}

/**
 * reads a datahandle yaml which is supposed to be formated as:
 * Hashes:
 *  - Hash1
 *  - Hash2
 *  .
 *  .
 *  - HashN
 * ColNames:
 *  - Col1
 *  - Col2
 *  .
 *  .
 *  - ColN
 */
int DataSet::read_data_handle(const std::string& filename)
{
    int success = -1;
    hashes.clear();
    columns.clear();

    try {
        YAML::Node top = YAML::LoadFile(filename);

        if (top["Hashes"])
        {
            YAML::Node colhashes = top["Hashes"];
            if (!colhashes.IsSequence())
            {
                std::cerr << "DataHandle is malformed" << std::endl;
                return success;
            }

            for(size_t i=0; i < colhashes.size(); ++i)
            {
                hashes.emplace_back(colhashes[i].as<std::string>());                
            }
        } else {
            std::cerr << "DataHandle is malformed: Missing Hashes" << std::endl;
            return success;
        }

        if (top["ColNames"])
        {
            YAML::Node colnames = top["ColNames"];
            if (!colnames.IsSequence())
            {
                std::cerr << "DataHandle is malformed" << std::endl;
                return success;
            }

            for(size_t i=0; i < colnames.size(); ++i)
            {
                columns.emplace_back(colnames[i].as<std::string>());                
            }
        } else {
            std::cerr << "DataHandle is malformed: Missing Columns" << std::endl;
            return success;
        }

    } catch(std::exception& e) {
        std::cerr << "Error reading the DataHandle :" << e.what() << std::endl;
        return success;
    }

    return 0;

}

/**
 * Get a jsonified document content
 * Useful for passing document content
 * to rest calls
 */
std::string DataSet::get_document_json()
{
    json j =  json::array();
    
    size_t nrows = num_rows();
    size_t ncols = num_cols();

    for(size_t i=0; i < ncols; ++i)
    {
        json jcol(get_column_as_string(i));
        j.push_back(jcol);
    }

    return j.dump();
}

/**
 * Get a jsonified data handle content
 * Useful for passing document hash to 
 * rest calls
 */
std::string DataSet::get_datahandle_json()
{
    json j;
    json jhashes(hashes);
    json jcolumns(columns);

    j["Hashes"] = jhashes;
    j["ColNames"] = jcolumns;

    return j.dump();
}

} // namespace


#endif