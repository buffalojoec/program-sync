/// Build a sparkline from a slice of values bucketed into `num_buckets` bins.
///
/// Values are linearly mapped across the `[min, max]` range. Returns a string
/// of Unicode bar characters where height is proportional to the bucket count.
///
/// An optional explicit maximum can be provided via `max_override` to extend the
/// range beyond the data (e.g., when the upper bound is known independently).
pub fn sparkline(values: &[i64], num_buckets: usize, max_override: Option<i64>) -> String {
    if values.is_empty() || num_buckets == 0 {
        return String::new();
    }

    let min = *values.iter().min().unwrap();
    let max = max_override
        .map(|m| m.max(min))
        .unwrap_or_else(|| *values.iter().max().unwrap());

    let range = max - min;
    if range == 0 {
        return BARS[7].to_string().repeat(num_buckets);
    }

    let bucket_width = (range as f64) / (num_buckets as f64);
    let mut buckets = vec![0u32; num_buckets];

    for &v in values {
        let idx = ((v - min) as f64 / bucket_width) as usize;
        buckets[idx.min(num_buckets - 1)] += 1;
    }

    let max_count = *buckets.iter().max().unwrap_or(&1);

    buckets
        .iter()
        .map(|&count| {
            if count == 0 {
                ' '
            } else {
                let level = ((count as f64 / max_count as f64) * 7.0) as usize;
                BARS[level.min(7)]
            }
        })
        .collect()
}

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
