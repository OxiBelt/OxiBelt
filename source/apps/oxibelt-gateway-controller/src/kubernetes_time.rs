//! Minimal UTC timestamp formatting for Kubernetes condition and Lease fields.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn rfc3339_now() -> String {
  let seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default();
  let days = seconds.div_euclid(86_400);
  let seconds_of_day = seconds.rem_euclid(86_400);
  let (year, month, day) = civil_from_days(days);
  let hour = seconds_of_day / 3_600;
  let minute = seconds_of_day % 3_600 / 60;
  let second = seconds_of_day % 60;
  format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
  let days = days_since_epoch + 719_468;
  let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
  let day_of_era = days - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let mut year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_prime = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
  let month = month_prime + if month_prime < 10 { 3 } else { -9 };
  if month <= 2 {
    year += 1;
  }
  (year, month as u32, day as u32)
}
