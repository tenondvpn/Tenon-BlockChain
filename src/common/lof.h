#pragma once

#include <stdarg.h>
#include <cassert>

#include <iostream>
#include <iterator>
#include <math.h>
#include <map>
#include <set>
#include <vector>

namespace tenon {

namespace common {

class Point {
public:
//     Point(int32_t node_count, int32_t idx, ...) {
//         dimension_ = node_count;
//         idx_ = idx;
//         va_list ap;
//         va_start(ap, dimension_);
//         double temp;
//         for (int32_t i = 0; i < dimension_; i++) {
//             temp = va_arg(ap, double);
//             coordinate_.push_back(temp);
//         }
// 
//         va_end(ap);
//     }
// 
    Point(int32_t node_count, int32_t idx) {
        dimension_ = node_count;
        idx_ = idx;
        for (int32_t i = 0; i < dimension_; i++) {
            coordinate_.push_back(0);
        }
    }

    ~Point() {
        coordinate_.clear();
    }

    double& operator [](int32_t idx) {
        return coordinate_[idx];
    }

    double operator [](int32_t idx) const {
        return coordinate_[idx];
    }

    void SetValue(int32_t index, double value) {
        assert(index < coordinate_.size());
        coordinate_.at(index) = value;

    }

    double GetValue(int32_t index) const {
        assert(index < coordinate_.size());
        return coordinate_.at(index);
    }

    int32_t GetDimension() const {
        return dimension_;
    }

    int32_t idx() const {
        return idx_;
    }

private:
    std::vector<double> coordinate_;
    int32_t dimension_{ -1 };
    int32_t idx_{ -1 };

};

class Lof {
public:
	Lof(std::vector<Point>& points);
	~Lof();
	double LocalOutlierFactor(int32_t min_point, int32_t point_idx);
    double KDistance(
        int32_t k,
        int32_t point_idx,
        const std::set<int32_t>& igns,
        std::vector<int32_t>* neighbours);
    double ReachabilityDist(
        int32_t k,
        int32_t point_idx,
        int32_t point_idx2,
        const std::set<int32_t>& igns);
    double LocalReachabilityDensity(
        int min_pts,
        int32_t point_idx,
        const std::set<int32_t>& igns);
    std::vector<int32_t> GetOutliers(int32_t k);

private:
    double PointDistEuclidean(const Point& l, const Point& r);

    std::vector<Point>& points_;
    int32_t now_point_idx_;

};

};  // namespace common

};  // namespace tenon
