#include <zkdoc/src/dataset-representation.hpp>
#include <zkdoc/src/httplib.h>
#include <unistd.h>

using namespace TrustedAI;

std::vector<std::vector<int>>
get_random_document(size_t nrows, size_t ncols)
{
    std::vector<std::vector<int>> doc(ncols, std::vector<int>(nrows, 0));

    for(size_t i=0; i < ncols; ++i)
        for(size_t j=0; j < nrows; ++j)
            doc[i][j] = std::rand() % 1000;
    
    return doc;
}

void write_csv(const std::vector<std::vector<int>>& doc, const std::vector<std::string>& header, const std::string& filename)
{
    std::ofstream out(filename);
    size_t nrows = doc[0].size();
    size_t ncols = doc.size();

    for(size_t i=0; i < header.size() - 1; ++i)
        out << header[i] << ",";
    
    out << header[header.size() - 1] << std::endl;

    for(size_t i=0; i < nrows; ++i)
    {
        for(size_t j=0; j < ncols - 1; ++j)
            out << doc[j][i] << ",";
        
        out << doc[ncols-1][i] << std::endl;
    }

    out.close();
}

void test_document_parsing()
{
    size_t n = 10;
    std::vector<std::string> colNames = {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"};
    auto doc = get_random_document(n, colNames.size());

    

    std::string mem_file = "/tmp/docfile";
    write_csv(doc, colNames, mem_file);

    DataSet d;
    d.read_data(mem_file);

    std::cout << "Read " << d.num_rows() << " rows, " << d.num_cols() << " columns" << std::endl;

    assert(d.num_rows() == n);
    assert(d.num_cols() == colNames.size());

    for(size_t i=0; i < colNames.size(); ++i)
    {
        assert(d.get_column_as_integer(i) == doc[i]);
    }

    std::cout << "Document content as json" << std::endl;

    std::cout << d.get_document_json();

}

void test_document_passing()
{
    size_t n = 10;
    std::vector<std::string> colNames = {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"};
    auto doc = get_random_document(n, colNames.size());

    

    std::string mem_file = "/tmp/docfile";
    write_csv(doc, colNames, mem_file);

    DataSet d;
    d.read_data(mem_file);

    std::cout << "Read " << d.num_rows() << " rows, " << d.num_cols() << " columns" << std::endl;

    assert(d.num_rows() == n);
    assert(d.num_cols() == colNames.size());

    for(size_t i=0; i < colNames.size(); ++i)
    {
        assert(d.get_column_as_integer(i) == doc[i]);
    }

    httplib::Params params;
    params.emplace("document-plaintext", d.get_document_json());

    httplib::Client cli("localhost:5000");
    auto res = cli.Post("/test/genhash", params);

    auto jres = json::parse(res->body);

    std::cout << jres.dump(4) << std::endl;
    std::cout << jres[0] << std::endl;
}


int main(int argc, char *argv[])
{
    test_document_parsing();
    test_document_passing();

    return 0;
}