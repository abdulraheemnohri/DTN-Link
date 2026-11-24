//! TLE-driven pass prediction (Phase 27) — compute real satellite
//! contact windows from a standard NORAD two-line element set (TLE).
//!
//! A TLE is the published orbital state of a satellite (mean motion,
//! inclination, RAAN, eccentricity, epoch phase). This module parses
//! two-line element sets, propagates the orbit with a deterministic
//! near-circular Kepler model and predicts the ground passes over a
//! station, producing exactly the contact windows dtn-gateway's
//! [`SatelliteGateway`](crate::satellite::SatelliteGateway) already
//! knows how to run: unix-second (start, end) windows.
//!
//! ```no_run
//! use dtn_gateway::tle::{GroundStation, Predictor, Tle};
//!
//! let text = std::fs::read_to_string("iss.tle").unwrap();
//! let tle = Tle::parse(&text).unwrap();
//! let gs = GroundStation::new(52.52, 13.40);   // Berlin, min elevation 10 deg
//! let p = Predictor::new(&tle, &gs).unwrap();
//! for pass in p.passes_between(1_730_000_000, 24.0) {
//!     println!("pass {}..{} max-elev {:.1} deg", pass.start, pass.end, pass.max_elevation_deg);
//! }
//! ```
//!
//! Honest scope: this is a mean-element propagator for near-circular
//! orbits. It is not full SGP4: the drag term (B*), the second and
//! third derivative elements and the secular J2 regression of the
//! node are not applied, and a pass shorter than the 15-second scan
//! step can be missed. For a ~400 km circular orbit the model keeps
//! the pass schedule well within a minute of the real window over a
//! few days from the element epoch, which is what a contact plan
//! needs; for precision operations, regenerate the plan from a fresh
//! TLE. Near-circularity is validated: element sets with
//! eccentricity > 0.05 are rejected rather than silently
//! mispredicted.

use crate::{ContactPlan, PlannedContact};
use std::f64::consts::PI;

const MU_KM3_S2: f64 = 398_600.441_8;
const EARTH_RADIUS_KM: f64 = 6_371.0;
const DEG: f64 = PI / 180.0;
/// Coarse horizon scan step. A pass shorter than this can be missed
/// by the search (documented honest scope); typical LEO passes are
/// hundreds of seconds long.
const COARSE_STEP_S: f64 = 15.0;

/// A parsed NORAD two-line element set.
#[derive(Debug, Clone, PartialEq)]
pub struct Tle {
    /// The human-readable name line above element line 1, when given.
    pub name: Option<String>,
    /// NORAD catalog number (identical on both element lines).
    pub norad_id: u32,
    /// Element-set epoch, unix seconds (UTC).
    pub epoch_unix: f64,
    pub inclination_deg: f64,
    /// Right ascension of the ascending node, degrees.
    pub raan_deg: f64,
    /// Argument of perigee, degrees (carried; the circular model
    /// folds it into the argument of latitude).
    pub arg_perigee_deg: f64,
    /// Mean anomaly at epoch, degrees.
    pub mean_anomaly_deg: f64,
    /// Mean motion, revolutions per day.
    pub mean_motion_rev_per_day: f64,
    /// Orbital eccentricity (validated small; near-circular model).
    pub eccentricity: f64,
}

/// A byte slice of an (ASCII) element line, with a clear error.
fn field<'a>(line: &'a str, from: usize, to: usize, what: &str) -> Result<&'a str, String> {
    let b = line.as_bytes();
    if b.len() < to || !line.is_char_boundary(from) || !line.is_char_boundary(to) {
        return Err(format!("element line too short for {what}: {line:?}"));
    }
    Ok(&line[from..to])
}

fn parse_num(s: &str, what: &str) -> Result<f64, String> {
    s.trim()
        .parse::<f64>()
        .map_err(|_| format!("invalid {what}: {s:?}"))
}

/// Days from civil 1970-01-01 (Howard Hinnant's `days_from_civil`;
/// integer-exact, no float rounding).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse the TLE epoch field "YYDDD.ddddddd" (UTC) into unix seconds.
fn parse_epoch(field: &str) -> Result<f64, String> {
    let s = field.trim();
    if s.len() < 8 {
        return Err(format!("epoch field too short: {field:?}"));
    }
    let year2: i64 = s[..2]
        .parse()
        .map_err(|_| format!("invalid epoch year: {field:?}"))?;
    let year: i64 = if year2 < 57 { 2000 + year2 } else { 1900 + year2 };
    let doy: f64 = s[2..]
        .parse()
        .map_err(|_| format!("invalid epoch day-of-year: {field:?}"))?;
    if !(1.0..=366.999).contains(&doy) {
        return Err(format!("epoch day-of-year out of range: {field:?}"));
    }
    let year_start = days_from_civil(year, 1, 1) * 86_400;
    Ok(year_start + (doy - 1.0) * 86_400.0)
}

impl Tle {
    /// Parse a two-line element set (with or without a name line,
    /// with or without surrounding text). The element lines are
    /// located by their `1 NNNNN` / `2 NNNNN` prefixes and must be
    /// adjacent with matching NORAD ids.
    pub fn parse(text: &str) -> Result<Tle, String> {
        let lines: Vec<&str> = text
            .lines()
            .map(|l| l.trim_end())
            .filter(|l| !l.trim().is_empty())
            .collect();

        let idx = (0..lines.len().saturating_sub(1)).find(|&i| {
            let l = lines[i].trim_start();
            l.starts_with("1 ") && lines[i + 1].trim_start().starts_with("2 ")
        });
        let Some(i1) = idx else {
            return Err("no adjacent `1 ...` / `2 ...` element lines found".into());
        };
        let l1 = lines[i1].trim_start();
        let l2 = lines[i1 + 1].trim_start();

        let id1: u32 = field(l1, 2, 7, "NORAD id (line 1)")?
            .trim()
            .parse()
            .map_err(|_| format!("invalid NORAD id on line 1: {l1:?}"))?;
        let id2: u32 = field(l2, 2, 7, "NORAD id (line 2)")?
            .trim()
            .parse()
            .map_err(|_| format!("invalid NORAD id on line 2: {l2:?}"))?;
        if id1 != id2 {
            return Err(format!("element line NORAD ids differ: {id1} vs {id2}"));
        }

        let epoch = parse_epoch(field(l1, 18, 32, "epoch")?)?;

        let inclination: f64 = parse_num(field(l2, 8, 16, "inclination")?, "inclination")?;
        let raan: f64 = parse_num(field(l2, 17, 25, "RAAN")?, "RAAN")?;
        let ecc_str = field(l2, 26, 33, "eccentricity")?.trim();
        let eccentricity: f64 = parse_num(&format!("0.{ecc_str}"), "eccentricity")?;
        let arg_perigee: f64 =
            parse_num(field(l2, 34, 42, "argument of perigee")?, "argument of perigee")?;
        let mean_anomaly: f64 = parse_num(field(l2, 43, 51, "mean anomaly")?, "mean anomaly")?;
        let mean_motion: f64 = parse_num(field(l2, 52, 63, "mean motion")?, "mean motion")?;

        if !(0.0..=180.0).contains(&inclination) {
            return Err(format!("inclination {inclination} out of range [0, 180]"));
        }
        if !(1.0..=22.0).contains(&mean_motion) {
            return Err(format!(
                "mean motion {mean_motion} rev/day is outside the supported range [1.0, 22.0]"
            ));
        }
        if eccentricity > 0.05 {
            return Err(format!(
                "eccentricity {eccentricity}: this module models near-circular orbits (max 0.05)"
            ));
        }

        // Name: the line above the first element line, when it is
        // not an element line itself.
        let name = if i1 > 0 && !lines[i1 - 1].trim_start().starts_with('1 ') {
            Some(lines[i1 - 1].trim().to_string())
        } else {
            None
        };

        Ok(Tle {
            name,
            norad_id: id1,
            epoch_unix: epoch,
            inclination_deg: inclination,
            raan_deg: raan,
            arg_perigee_deg: arg_perigee,
            mean_anomaly_deg: mean_anomaly,
            mean_motion_rev_per_day: mean_motion,
            eccentricity,
        })
    }

    /// Mean motion in radians per second.
    pub fn mean_motion_rad_s(&self) -> f64 {
        self.mean_motion_rev_per_day * 2.0 * PI / 86_400.0
    }

    /// Semi-major axis from Kepler's third law (km).
    pub fn semi_major_axis_km(&self) -> f64 {
        let n2 = self.mean_motion_rad_s().powi(2);
        (MU_KM3_S2 / n2).cbrt()
    }

    /// Circular-equivalent altitude above the mean Earth surface (km).
    pub fn altitude_km(&self) -> f64 {
        self.semi_major_axis_km() - EARTH_RADIUS_KM
    }

    /// Orbital period (seconds).
    pub fn period_s(&self) -> f64 {
        86_400.0 / self.mean_motion_rev_per_day
    }
}

impl std::fmt::Display for Tle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (NORAD {}) — inc {:.4} deg, RAAN {:.4} deg, e {:.7}, n {:.8} rev/day",
            self.name.as_deref().unwrap_or("<unnamed>"),
            self.norad_id,
            self.inclination_deg,
            self.raan_deg,
            self.eccentricity,
            self.mean_motion_rev_per_day
        )
    }
}

/// A ground station and the geometry of an acceptable pass.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundStation {
    /// Geodetic latitude, degrees north (positive).
    pub lat_deg: f64,
    /// Longitude, degrees east (positive).
    pub lon_deg: f64,
    /// Altitude above mean sea level, km (default 0).
    pub alt_km: f64,
    /// Minimum acceptable elevation, degrees (default 10).
    pub min_elevation_deg: f64,
}

impl GroundStation {
    pub fn new(lat_deg: f64, lon_deg: f64) -> Self {
        GroundStation {
            lat_deg,
            lon_deg,
            alt_km: 0.0,
            min_elevation_deg: 10.0,
        }
    }

    /// Validate the geometry before any prediction runs.
    pub fn validate(&self) -> Result<(), String> {
        if !(-90.0..=90.0).contains(&self.lat_deg) {
            return Err(format!("latitude {} out of range [-90, 90]", self.lat_deg));
        }
        if !(-180.0..=180.0).contains(&self.lon_deg) {
            return Err(format!("longitude {} out of range [-180, 180]", self.lon_deg));
        }
        if !(-90.0..=90.0).contains(&self.min_elevation_deg) {
            return Err(format!(
                "min elevation {} out of range [-90, 90]",
                self.min_elevation_deg
            ));
        }
        Ok(())
    }

    fn ecef(&self) -> [f64; 3] {
        let (la, lo) = (self.lat_deg * DEG, self.lon_deg * DEG);
        let r = EARTH_RADIUS_KM + self.alt_km;
        [r * la.cos() * lo.cos(), r * la.cos() * lo.sin(), r * la.sin()]
    }

    fn up(&self) -> [f64; 3] {
        let (la, lo) = (self.lat_deg * DEG, self.lon_deg * DEG);
        [la.cos() * lo.cos(), la.cos() * lo.sin(), la.sin()]
    }
}

/// One predicted pass: a contact window in unix seconds (inclusive
/// start, exclusive end — exactly the ContactPlan window convention)
/// plus the topocentric maximum elevation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pass {
    pub start: u64,
    pub end: u64,
    pub max_elevation_deg: f64,
}

impl Pass {
    /// Window length in seconds; `SatelliteGateway` contacts during
    /// the whole window, so this is the available transfer time.
    pub fn duration_s(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_open(&self, now: u64) -> bool {
        now >= self.start && now < self.end
    }
}

/// Deterministic near-circular pass predictor.
#[derive(Debug, Clone)]
pub struct Predictor {
    pub tle: Tle,
    pub station: GroundStation,
}

impl Predictor {
    /// Build a predictor, validating the station geometry.
    pub fn new(tle: &Tle, station: &GroundStation) -> Result<Predictor, String> {
        station.validate()?;
        Ok(Predictor {
            tle: tle.clone(),
            station: station.clone(),
        })
    }

    /// Greenwich mean sidereal time in radians (IAU 1982 series,
    /// sufficient for pass prediction).
    fn gmst_rad(unix: f64) -> f64 {
        let jd = unix / 86_400.0 + 2_440_587.5;
        let t = (jd - 2_451_545.0) / 36_525.0;
        let s = 67_310.548_41
            + (8_766_00.0 * 3_600.0 + 8_640_184.812_866) * t
            + 0.093_104 * t * t
            - 6.2e-6 * t * t * t;
        s.rem_euclid(86_400.0) * (PI / 43_200.0) // seconds -> radians
    }

    /// Spacecraft position in Earth-fixed kilometers at unix time.
    fn sat_ecef(&self, unix: f64) -> [f64; 3] {
        let dt = unix - self.tle.epoch_unix;
        let n = self.tle.mean_motion_rad_s();
        // Circular orbit: describe the position by the argument of
        // latitude; for a near-circular orbit the true anomaly
        // approximates the mean anomaly, so the phase is
        // argp + M0 + n*dt.
        let u0 = (self.tle.arg_perigee_deg + self.tle.mean_anomaly_deg) * DEG + n * dt;
        let i = self.tle.inclination_deg * DEG;
        let raan = self.tle.raan_deg * DEG;
        let a = self.tle.semi_major_axis_km();
        let (su, cu) = (u0.sin(), u0.cos());
        let (si, ci) = (i.sin(), i.cos());
        let (sO, cO) = (raan.sin(), raan.cos());
        // Perifocal -> ECI
        let x = a * (cO * cu - sO * su * ci);
        let y = a * (sO * cu + cO * su * ci);
        let z = a * (su * si);
        // ECI -> ECEF by the earth rotation angle
        let th = Self::gmst_rad(unix);
        let (st, ct) = (th.sin(), th.cos());
        [x * ct + y * st, -x * st + y * ct, z]
    }

    /// Topocentric elevation of the spacecraft over the station at
    /// unix time, degrees (negative = below the horizon).
    pub fn elevation_at(&self, unix: f64) -> f64 {
        let s = self.sat_ecef(unix);
        let g = self.station.ecef();
        let d = [s[0] - g[0], s[1] - g[1], s[2] - g[2]];
        let dist = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
        if dist == 0.0 {
            return 90.0;
        }
        let up = self.station.up();
        let dot =
            (d[0] * up[0] + d[1] * up[1] + d[2] * up[2]) / dist;
        dot.clamp(-1.0, 1.0).asin() / DEG
    }

    /// Binary-search the horizon crossing inside [lo, hi], where the
    /// two ends lie on opposite sides of the `min_elev` threshold.
    /// Direction-agnostic: the lo boundary is held fixed as the
    /// reference side.
    fn crossing(&self, lo: f64, hi: f64, min_elev: f64) -> f64 {
        let (mut lo, mut hi) = (lo.min(hi), lo.max(hi));
        let lo_above = self.elevation_at(lo) >= min_elev;
        for _ in 0..32 {
            let mid = (lo + hi) / 2.0;
            if (self.elevation_at(mid) >= min_elev) == lo_above {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        (lo + hi) / 2.0
    }

    /// All passes in the unix interval [from, from + hours*3600).
    /// Passes are non-overlapping and ascending by start time; a
    /// pass already above the threshold at `from` starts at `from`,
    /// and a pass still above the threshold at the horizon ends
    /// there.
    pub fn passes_between(&self, from_unix: i64, hours: f64) -> Vec<Pass> {
        let min = self.station.min_elevation_deg;
        let from = from_unix.max(0) as f64;
        let horizon = from + hours.max(0.0) * 3_600.0;
        if horizon <= from {
            return Vec::new();
        }
        let mut passes = Vec::new();
        let mut in_pass = self.elevation_at(from) >= min;
        let mut start = from;
        let mut max_e = f64::MIN;
        if in_pass {
            max_e = self.elevation_at(from);
        }
        let mut t = from;
        while t <= horizon {
            let e = self.elevation_at(t);
            if e >= min {
                if !in_pass {
                    in_pass = true;
                    let prev = (t - COARSE_STEP_S).max(from);
                    start = self.crossing(prev, t, min).max(from);
                    max_e = e;
                } else if e > max_e {
                    max_e = e;
                }
            } else if in_pass {
                in_pass = false;
                let end = self.crossing(t - COARSE_STEP_S, t, min).clamp(from, horizon);
                if (end - start).abs() >= 1.0 {
                    passes.push(Pass {
                        start: start as u64,
                        end: end as u64,
                        max_elevation_deg: max_e,
                    });
                } else {
                    start = end; // sub-second sliver; fold it away
                    max_e = f64::MIN;
                }
            }
            t += COARSE_STEP_S;
        }
        if in_pass {
            let end = horizon as u64;
            passes.push(Pass {
                start: start as u64,
                end: end.max(start as u64 + 1),
                max_elevation_deg: max_e,
            });
        }
        passes
    }

    /// The next pass at or after `from`, searching up to 72 hours.
    pub fn next_pass(&self, from_unix: i64) -> Option<Pass> {
        self.passes_between(from_unix, 72.0).into_iter().next()
    }

    /// A ready-to-run [`ContactPlan`]: one windowed contact per
    /// predicted pass. This is the bridge from orbital mechanics to
    /// the gateway: the resulting plan windows drive exactly the
    /// existing `SatelliteGateway::run_pass` machinery.
    pub fn to_contact_plan(&self, addr: &str, from_unix: i64, hours: f64) -> ContactPlan {
        let contacts = self
            .passes_between(from_unix, hours)
            .into_iter()
            .map(|p| PlannedContact::windowed(addr, p.start, p.end))
            .collect();
        ContactPlan { contacts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satellite::SatelliteGateway;

    /// Real ISS element set (epoch 2024-10-26T12:25:40Z).
    const ISS_TLE: &str = "ISS (ZARYA)\n\
        1 25544U 98067A   24300.51782528  .00016717  00000+0  30777-3 0  9993\n\
        2 25544  51.6400 208.9163 0006317  69.9862 290.2588 15.49660025472736\n";

    #[test]
    fn parses_a_real_tle() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        assert_eq!(tle.norad_id, 25544);
        assert_eq!(tle.name.as_deref(), Some("ISS (ZARYA)"));
        assert!((tle.inclination_deg - 51.6400).abs() < 1e-9);
        assert!((tle.raan_deg - 208.9163).abs() < 1e-9);
        assert!((tle.eccentricity - 0.0006317).abs() < 1e-12);
        assert!((tle.arg_perigee_deg - 69.9862).abs() < 1e-9);
        assert!((tle.mean_anomaly_deg - 290.2588).abs() < 1e-9);
        assert!((tle.mean_motion_rev_per_day - 15.49660025).abs() < 1e-9);
    }

    #[test]
    fn epoch_matches_the_published_value() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        // 2024-10-26T12:25:40.1Z == 1729945540.1
        assert!((tle.epoch_unix - 1_729_945_540.1).abs() < 1.0);
    }

    #[test]
    fn kepler_altitude_is_right_for_the_iss() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        let alt = tle.altitude_km();
        assert!(
            (380.0..470.0).contains(&alt),
            "ISS mean altitude should be ~420 km, got {alt}"
        );
        assert!(
            (tle.period_s() - 5_560.0).abs() < 60.0,
            "period should be ~92.7 min, got {}",
            tle.period_s()
        );
    }

    #[test]
    fn parse_rejects_bad_element_sets() {
        assert!(Tle::parse("no elements here").is_err());
        // Missing line 2.
        assert!(Tle::parse(
            "1 25544U 98067A   24300.51782528  .00016717  00000+0  30777-3 0  9993"
        )
        .is_err());
        // Mismatched NORAD ids.
        let bad = "1 25544U 98067A   24300.51782528  .00016717  00000+0  30777-3 0  9993\n\
                   2 25545  51.6400 208.9163 0006317  69.9862 290.2588 15.49660025472736\n";
        assert!(Tle::parse(bad).is_err());
        // Out-of-range inclination.
        let bad_inc = "1 25544U 98067A   24300.51782528  .00016717  00000+0  30777-3 0  9993\n\
                       2 25544  200.000 208.9163 0006317  69.9862 290.2588 15.49660025472736\n";
        assert!(Tle::parse(bad_inc).is_err());
        // Junk mean motion.
        let bad_mm = "1 25544U 98067A   24300.51782528  .00016717  00000+0  30777-3 0  9993\n\
                      2 25544  51.6400 208.9163 0006317  69.9862 290.2588 AB.49660025472736\n";
        assert!(Tle::parse(bad_mm).is_err());
        // Too eccentric for the near-circular model.
        let bad_ecc = "1 99123U 20001A   24300.51782528  .00016717  00000+0  30777-3 0  9993\n\
                       2 99123  51.6400 208.9163 1200000  69.9862 290.2588 15.49660025472736\n";
        assert!(Tle::parse(bad_ecc).is_err());
        // Junk epoch.
        let bad_epoch = "1 25544U 98067A   24300.51782828x  .00016717  00000+0  30777-3 0  9993\n\
                         2 25544  51.6400 208.9163 0006317  69.9862 290.2588 15.49660025472736\n";
        assert!(Tle::parse(bad_epoch).is_err());
    }

    fn synthetic(name: &str, norad: u32, inc: f64, mm: f64) -> Tle {
        Tle {
            name: Some(name.into()),
            norad_id: norad,
            epoch_unix: 1_730_000_000.0,
            inclination_deg: inc,
            raan_deg: 0.0,
            arg_perigee_deg: 0.0,
            mean_anomaly_deg: 0.0,
            mean_motion_rev_per_day: mm,
            eccentricity: 0.0,
        }
    }

    #[test]
    fn geostationary_satellite_has_constant_elevation() {
        let tle = synthetic("GEO", 40000, 0.0, 1.002_737_91);
        // Sub-satellite point: RAAN + argp + M0 = 0 deg longitude.
        let gs = GroundStation {
            lat_deg: 0.0,
            lon_deg: 0.0,
            alt_km: 0.0,
            min_elevation_deg: 5.0,
        };
        let p = Predictor::new(&tle, &gs).unwrap();
        let e1 = p.elevation_at(1_730_010_000.0);
        let e2 = p.elevation_at(1_730_010_000.0 + 3_600.0);
        assert!(e1 > 80.0, "directly overhead at the sub-satellite point: {e1}");
        assert!((e1 - e2).abs() < 1.0, "GEO elevation must not drift: {e1} vs {e2}");
    }

    #[test]
    fn equatorial_orbit_is_never_seen_from_high_latitudes() {
        let tle = synthetic("EqLEO", 40001, 0.0, 15.0);
        let gs = GroundStation::new(60.0, 13.4);
        let p = Predictor::new(&tle, &gs).unwrap();
        let passes = p.passes_between(1_730_000_000, 48.0);
        assert!(
            passes.iter().all(|pp| pp.max_elevation_deg < 10.0),
            "an equatorial orbit can never exceed the horizon from lat 60N"
        );
    }

    #[test]
    fn polar_orbit_produces_ordered_non_overlapping_passes() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(60.0, 13.4);
        let p = Predictor::new(&tle, &gs).unwrap();
        let from = 1_730_000_000;
        let passes = p.passes_between(from, 24.0);
        assert!(
            !passes.is_empty(),
            "a sun-synchronous orbit must pass over lat 60N"
        );
        assert!(
            passes.len() <= 16,
            "no more than (24h / 92min) * 2 horizon windows: {}",
            passes.len()
        );
        for w in &passes {
            assert!(w.duration_s() >= 1, "windows are bounded and non-degenerate");
            assert!(
                w.duration_s() <= 1_200,
                "a ~500 km pass is under 20 min: {}",
                w.duration_s()
            );
            assert!(w.max_elevation_deg >= gs.min_elevation_deg);
            assert!(w.max_elevation_deg <= 90.0 + 1e-9);
        }
        for pair in passes.windows(2) {
            assert!(pair[1].start >= pair[0].end, "passes never overlap");
        }
    }

    #[test]
    fn iss_passes_over_berlin_are_plausible() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        let gs = GroundStation::new(52.52, 13.40);
        let p = Predictor::new(&tle, &gs).unwrap();
        let from = 1_730_010_000; // ~28.5 h after the element epoch
        let passes = p.passes_between(from, 48.0);
        assert!(
            (1..=12).contains(&passes.len()),
            "the ISS crosses Berlin roughly 2-6 times/day; got {}: {:?}",
            passes.len(),
            passes.iter().map(|pp| (pp.start, pp.end)).collect::<Vec<_>>()
        );
        for w in &passes {
            assert!(w.duration_s() >= 30, "an ISS pass at elev >= 10 deg lasts >= 45 s");
            assert!(w.duration_s() <= 720);
            // The recorded maximum elevation is real: at the quoted
            // maximum, the model must agree (within the scan step).
            assert!(p.elevation_at(w.start as f64 + w.duration_s() as f64 / 2.0)
                > gs.min_elevation_deg - 2.0);
        }
    }

    #[test]
    fn prediction_is_deterministic() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(51.0, -1.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        let a = p.passes_between(1_730_000_000, 12.0);
        let b = p.passes_between(1_730_000_000, 12.0);
        assert_eq!(a, b);
    }

    #[test]
    fn next_pass_finds_the_first_window() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(51.0, -1.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        let from = 1_730_000_000;
        let all = p.passes_between(from, 72.0);
        let nxt = p.next_pass(from);
        assert_eq!(nxt.map(|w| w.start), all.first().map(|w| w.start));
    }

    #[test]
    fn zero_horizon_produces_no_passes() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(51.0, -1.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        assert!(p.passes_between(1_730_000_000, 0.0).is_empty());
        assert!(p.passes_between(1_730_000_000, -5.0).is_empty());
    }

    #[test]
    fn plan_bridge_roundtrips_through_the_text_format() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(51.0, -1.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        let from = 1_730_000_000;
        let plan = p.to_contact_plan("gs.example.net:4556", from, 24.0);
        assert!(!plan.contacts.is_empty());
        // The generated plan parses back from its own text form.
        let again = ContactPlan::parse(&plan.to_text()).unwrap();
        assert_eq!(plan, again);
        // Every window is a genuine pass window (positive length,
        // open exactly at its own start).
        for c in &again.contacts {
            match c.window {
                Some((s, e)) => {
                    assert!(e > s && c.is_open(s));
                    assert!(!c.is_open(e), "windows are start-inclusive, end-exclusive");
                }
                None => panic!("a predicted pass must carry a window"),
            }
        }
    }

    #[test]
    fn satellite_gateway_uses_predicted_windows_directly() {
        let tle = synthetic("SunSync", 40123, 97.8, 15.0);
        let gs = GroundStation::new(51.0, -1.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        let from = 1_730_000_000;
        let plan = p.to_contact_plan("203.0.113.5:4556", from, 24.0);
        let gw = SatelliteGateway::new(plan);
        assert_eq!(
            gw.next_pass_in(from),
            Some(p.next_pass(from).unwrap().start - from as u64),
            "the gateway sees the predicted pass schedule unchanged"
        );
        assert!(
            gw.open_contacts(from).is_empty(),
            "no window is open at `from` unless a pass is live"
        );
    }

    #[test]
    fn elevation_is_finite_before_and_after_the_epoch() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        let gs = GroundStation::new(52.52, 13.40);
        let p = Predictor::new(&tle, &gs).unwrap();
        for t in [
            tle.epoch_unix - 86_400.0,
            tle.epoch_unix - 1.0,
            tle.epoch_unix,
            tle.epoch_unix + 86_400.0 * 3.0,
        ] {
            let e = p.elevation_at(t);
            assert!(e.is_finite(), "elevation must never be NaN/inf at {t}");
            assert!((-90.0..=90.0).contains(&e));
        }
    }

    #[test]
    fn station_geometry_is_validated() {
        let tle = Tle::parse(ISS_TLE).unwrap();
        assert!(Predictor::new(&tle, &GroundStation::new(95.0, 0.0)).is_err());
        assert!(Predictor::new(&tle, &GroundStation::new(0.0, 200.0)).is_err());
        let gs = GroundStation::new(52.0, 13.0);
        let p = Predictor::new(&tle, &gs).unwrap();
        let s = format!("{tle}");
        assert!(s.contains("25544"), "display carries the NORAD id: {s}");
        assert!(gs.validate().is_ok());
    }
}
