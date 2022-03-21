#include "common/lof.h"

namespace tenon {

namespace common {

Lof::Lof(std::vector<Point>& points) : points_(points) {}

Lof::~Lof() {}

double Lof::LocalOutlierFactor(int32_t min_point, int32_t point_idx) {
    std::vector<int32_t> neighbours;
    KDistance(min_point, point_idx, std::set<int32_t>(), &neighbours);
    double instance_lrd = LocalReachabilityDensity(min_point, point_idx, std::set<int32_t>());
    std::vector<double> lrd_ratios;
    for (auto iter = neighbours.begin(); iter != neighbours.end(); ++iter) {
        std::set<int32_t> igns;
        igns.insert(*iter);
        auto neighbour_lrd = LocalReachabilityDensity(min_point, *iter, igns);
        lrd_ratios.push_back(neighbour_lrd / instance_lrd);
    }

    double sum = 0;
    for (uint32_t i = 0; i < lrd_ratios.size(); i++) {
        sum += (double)lrd_ratios[i];
    }

    return sum / (double)neighbours.size();
}

double Lof::KDistance(
        int32_t k,
        int32_t point_idx,
        const std::set<int32_t>& igns,
        std::vector<int32_t>* neighbours) {
    static const double kScaleValue = 1000000.0;
    std::map<int64_t, std::vector<int32_t>> dist_map;
    for (uint32_t i = 0; i < points_.size(); i++) {
        if (igns.find(points_[i].idx()) != igns.end() || points_[i].idx() == now_point_idx_) {
            continue;
        }

        auto dist = PointDistEuclidean(points_[point_idx], points_[i]);
        int64_t int_val = static_cast<int64_t>(dist * kScaleValue);
        auto iter = dist_map.find(int_val);
        if (iter != dist_map.end()) {
            dist_map[int_val].push_back(points_[i].idx());
        } else  {
            std::vector<int32_t> vec_temp;
            vec_temp.push_back(points_[i].idx());
            dist_map.insert(std::pair<int64_t, std::vector<int32_t>>(int_val, vec_temp));
        }
    }

    int32_t k_sero = 0;
    double k_dist;
    for (auto iter = dist_map.begin(); iter != dist_map.end(); ++iter) {
        k_sero += iter->second.size();
        for (uint32_t i = 0; i < iter->second.size(); i++) {
            neighbours->push_back(iter->second[i]);
        }

        k_dist = (double)iter->first / kScaleValue;
        if (k_sero >= k) {
            break;
        }
    }

    return k_dist;
}

double Lof::ReachabilityDist(
        int32_t k,
        int32_t point_idx,
        int32_t point_idx2,
        const std::set<int32_t>& igns) {
    std::vector<int32_t> neighbours;
    double k_dist = KDistance(k, point_idx2, igns, &neighbours);
    double dist = PointDistEuclidean(points_[point_idx], points_[point_idx2]);
    if (k_dist > dist) {
        return k_dist;
    }
        
    return dist;
}

double Lof::LocalReachabilityDensity(
        int min_pts,
        int32_t point_idx,
        const std::set<int32_t>& igns) {
    std::vector<int32_t> neighbours;
    KDistance(min_pts, point_idx, igns, &neighbours);
    double sumReachDist = 0.0;
    for (auto iter = neighbours.begin(); iter != neighbours.end(); ++iter) {
        auto res = ReachabilityDist(
            min_pts,
            point_idx,
            *iter,
            igns);
        sumReachDist += res;
    }

    if (sumReachDist <= 0.00000001) {
        return -99999999.99;
    }

    return (double)neighbours.size() / sumReachDist;
}

std::vector<std::pair<int32_t, double>> Lof::GetOutliers(int32_t k) {
    std::vector<Point> vec_InstancesBackUp;
    std::vector<std::pair<int32_t, double>> res_vec;
    for (uint32_t i = 0; i < points_.size(); i++) {
        now_point_idx_ = i;
        double value = LocalOutlierFactor(k, i);
        if (value > 1.0) {
            res_vec.push_back(std::pair<int32_t, double>(i, value));
        }
    }

    return res_vec;
}

double Lof::PointDistEuclidean(const Point& l, const Point& r) {
    int32_t dimension = l.GetDimension();
    std::vector<double>differences(dimension, 0.0);
    for (int32_t i = 0; i < dimension; i++) {
        differences[i] = l[i] - r[i];
    }

    double sum = 0.0;
    for (int32_t i = 0; i < dimension; i++) {
        sum += differences[i] * differences[i];
    }

    return std::sqrt(sum / (double)dimension);
}

};  // namespace common

};  // namespace tenon
