#pragma once

#include "common/utils.h"

namespace tenon {

namespace common {

template <class DataType>
void ReadDataFromFile(std::string &filename, std::vector<std::vector<DataType>> &lines_feat) {
    std::ifstream vm_info(filename.c_str());
    std::string lines;
    DataType var;
    std::vector<DataType> row;

    lines_feat.clear();

    while (!vm_info.eof()) {
        getline(vm_info, lines);
        if (lines.empty())
            break;
        std::stringstream stringin(lines);
        row.clear();

        while (stringin >> var) {
            row.push_back(var);
        }
        lines_feat.push_back(row);
    }
}

template <class DataType>
void Display2DVector(std::vector<std::vector<DataType>> &vv) {
    std::cout << "the total rows of 2d vector_data: " << vv.size() << "\n";

    for (size_t i = 0; i < vv.size(); ++i) {
        for (typename::std::vector<DataType>::const_iterator it = vv[i].begin(); it != vv[i].end(); ++it) {
            std::cout << *it << " ";
        }
        std::cout << "\n";
    }
    std::cout << "--------the end of the Display2DVector()--------\n";
}

template <class DataType>
void ProcessVector(std::vector<std::vector<DataType>> &vv) {
    std::vector<double> temp;
    double u[3] = { 0.0 }, sum[3] = { 0.0 }, sigma[3] = { 0.0 };
    for (size_t j = 0; j < 3; ++j) {
        temp.clear();
        for (size_t i = 0; i < vv.size(); ++i) {
            temp.push_back(vv[i][j]);
        }
        sum[j] = std::accumulate(temp.begin(), temp.end(), 0);
        u[j] = sum[j] / vv.size();
    }

    for (size_t j = 0; j < 3; ++j) {
        temp.clear();
        sum[j] = 0.0;
        for (size_t i = 0; i < vv.size(); ++i) {
            temp.push_back(std::pow(vv[i][j] - u[j], 2.0));
        }
        sum[j] = std::accumulate(temp.begin(), temp.end(), 0.0);
        sigma[j] = sum[j] / vv.size();
        sigma[j] = sqrt(sigma[j]);
    }

    double MaxValue[3] = { 0.0 }, MinValue[3] = { 0.0 };
    for (size_t j = 0; j < 3; ++j) {
        temp.clear();
        for (size_t i = 0; i < vv.size(); ++i) {
            if ((vv[i][j] > (u[j] - 3 * sigma[j])) && (vv[i][j] < (u[j] + 3 * sigma[j]))) {
                std::cout << vv[i][j] << " ";
                temp.push_back(vv[i][j]);
            }
        }
        std::cout << "\n";
        MaxValue[j] = *std::max_element(temp.begin(), temp.end());
        MinValue[j] = *std::min_element(temp.begin(), temp.end());
    }

    for (size_t j = 0; j < 3; ++j) {
        for (size_t i = 0; i < vv.size(); ++i) {
            if ((vv[i][j] > (u[j] - 3 * sigma[j])) && (vv[i][j] < (u[j] + 3 * sigma[j]))) {
                std::cout << (vv[i][j] - MinValue[j]) / (MaxValue[j] - MinValue[j]) << " ";
            }
        }
        std::cout << "\n";
    }
}

class DataSmooth {
public:
    DataSmooth();
    ~DataSmooth();

private:

};

};  // namespace common

};  // namespace tenon