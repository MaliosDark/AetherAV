//! Streaming statistics for online learning.
//!
//! Welford's algorithm tracks mean and variance in a single pass with O(1)
//! state, so the baseline can be updated incrementally as new telemetry arrives
//! no retraining, no storing raw samples. That is the "lightweight online
//! learning" the engine needs to adapt to a host without a restart.

use serde::{Deserialize, Serialize};

/// Running mean/variance over a stream of `f64` observations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunningStats {
    n: u64,
    mean: f64,
    /// Sum of squares of differences from the running mean (Welford's M2).
    m2: f64,
}

impl RunningStats {
    /// Fold one observation into the running statistics.
    pub fn observe(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn count(&self) -> u64 {
        self.n
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Sample variance (Bessel-corrected). Zero with fewer than two samples.
    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n - 1) as f64
        }
    }

    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Standard score of `x`. Returns 0.0 when there is no spread (or too few
    /// samples) so a flat baseline never manufactures anomalies.
    pub fn zscore(&self, x: f64) -> f64 {
        let sd = self.stddev();
        if sd <= 1e-9 {
            0.0
        } else {
            (x - self.mean) / sd
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_mean_and_variance() {
        let mut s = RunningStats::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            s.observe(x);
        }
        assert!((s.mean() - 5.0).abs() < 1e-9);
        // Sample variance of this classic dataset is 32/7 ≈ 4.571.
        assert!((s.variance() - (32.0 / 7.0)).abs() < 1e-9);
    }

    #[test]
    fn flat_baseline_has_no_zscore() {
        let mut s = RunningStats::default();
        for _ in 0..10 {
            s.observe(3.0);
        }
        assert_eq!(s.zscore(3.0), 0.0);
        assert_eq!(s.zscore(100.0), 0.0); // no spread -> no anomaly
    }

    #[test]
    fn outlier_has_high_zscore() {
        let mut s = RunningStats::default();
        for x in [10.0, 11.0, 9.0, 10.0, 10.0, 11.0, 9.0] {
            s.observe(x);
        }
        assert!(s.zscore(200.0) > 5.0);
    }
}
