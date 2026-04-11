"""
SQLite Learning System — Application Stack Traceroute v4.1
==========================================================
Modulo di persistenza e apprendimento adattivo.

Principio: Warm-start con fallback graceful.
Prior statici finché non c'è abbastanza evidenza empirica (n_weighted basso),
poi i dati prendono il controllo, con safety net che rileva regressioni.

Separazione tool: traceroute e crawler hanno contatori indipendenti;
i dati di target sono condivisi (se traceroute ha profilato un target,
crawler ne beneficia).

Schema versione: 1 (migrazioni future useranno schema_version per upgrade).
"""

import json
import math
import sqlite3
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ===========================================================================
# Helper functions (esposte anche dal package __init__)
# ===========================================================================

def _hash_target(url: str) -> str:
    """sha256(netloc)[:16] — identificatore compatto e privato del target."""
    netloc = urlparse(url).netloc
    return hashlib.sha256(netloc.encode()).hexdigest()[:16]


def _build_stack_signature(stack_layers: list) -> str:
    """JSON compatto {cdn, waf, backend} dalla lista layer dello stack."""
    sig = {
        'cdn': next(
            (l['component'] for l in stack_layers if l.get('type') == 'CDN'), None
        ),
        'waf': next(
            (l['component'] for l in stack_layers if l.get('type') == 'WAF'), None
        ),
        'backend': next(
            (l['component'] for l in stack_layers if l.get('type') == 'BACKEND'), None
        ),
    }
    return json.dumps(sig, sort_keys=True)


# ===========================================================================
# Valori statici di fallback — usati come prior iniziali
# ===========================================================================

# Latenze medie attese per CDN type (ms)
_STATIC_TIMING: dict = {
    'cloudflare':  {'avg_ms': 20,  'jitter': 15},
    'akamai':      {'avg_ms': 30,  'jitter': 20},
    'fastly':      {'avg_ms': 15,  'jitter': 10},
    'aws_cloudfront': {'avg_ms': 25, 'jitter': 18},
    'generic':     {'avg_ms': 50,  'jitter': 30},
}

# Prior statici per LR scalars anomalia (usati da advanced_bypass_engine)
# Rappresentano quanto ogni tipo di anomalia aumenta la probabilità di bypass reale.
# Aggiornati empiricamente da _update_lr_scalars() quando ci sono abbastanza dati.
_STATIC_LR_SCALARS: dict = {
    'size_anomaly':      2.0,
    'timing_anomaly':    3.0,
    'entropy_diff':      5.0,
    'new_headers':       15.0,
    'missing_headers':   8.0,
    'error_sig_changed': 25.0,
    'reflection':        20.0,
    'multi_dim':         15.0,
}

# Prior statici per tecnica di bypass
_STATIC_TECHNIQUE_PRIORS: dict = {
    'header_manipulation': {'success_probability': 0.35, 'detection_risk': 0.20},
    'path_traversal':      {'success_probability': 0.25, 'detection_risk': 0.15},
    'method_override':     {'success_probability': 0.20, 'detection_risk': 0.10},
    'encoding_evasion':    {'success_probability': 0.30, 'detection_risk': 0.18},
    'referer_spoofing':    {'success_probability': 0.15, 'detection_risk': 0.08},
    'semantic_bypass':     {'success_probability': 0.20, 'detection_risk': 0.12},
    'graph_optimized':     {'success_probability': 0.25, 'detection_risk': 0.15},
}

# Schema SQL completo
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tool            TEXT    NOT NULL CHECK(tool IN ('traceroute', 'crawler')),
    target_hash     TEXT    NOT NULL,
    target_domain   TEXT    NOT NULL,
    scan_ts         REAL    NOT NULL,
    scan_duration_s REAL,
    stack_signature TEXT,
    outcome_summary TEXT
);

CREATE TABLE IF NOT EXISTS timing_baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_hash TEXT    NOT NULL,
    cdn_type    TEXT    NOT NULL,
    tool        TEXT    NOT NULL CHECK(tool IN ('traceroute', 'crawler')),
    latency_ms  REAL    NOT NULL,
    scan_id     INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS technique_outcomes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT    NOT NULL,
    tool            TEXT    NOT NULL DEFAULT 'traceroute'
                    CHECK(tool IN ('traceroute', 'crawler')),
    stack_signature TEXT    NOT NULL,
    success         INTEGER NOT NULL CHECK(success IN (0, 1)),
    detected        INTEGER NOT NULL DEFAULT 0 CHECK(detected IN (0, 1)),
    scan_id         INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at     REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_weights (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_type    TEXT    NOT NULL,
    tool             TEXT    NOT NULL CHECK(tool IN ('traceroute', 'crawler')),
    context          TEXT,
    likelihood_ratio REAL    NOT NULL,
    was_true_positive INTEGER NOT NULL CHECK(was_true_positive IN (0, 1)),
    scan_id          INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at      REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS bypassability_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    error_type      TEXT    NOT NULL,
    stack_signature TEXT    NOT NULL,
    actual_bypassed INTEGER NOT NULL CHECK(actual_bypassed IN (0, 1)),
    scan_id         INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at     REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_test_limits (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_type      TEXT    NOT NULL,
    target_hash    TEXT    NOT NULL,
    tests_run      INTEGER NOT NULL,
    true_positives INTEGER NOT NULL DEFAULT 0,
    scan_id        INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS timing_thresholds (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    threshold_id  TEXT    NOT NULL,
    tool          TEXT    NOT NULL CHECK(tool IN ('traceroute', 'crawler')),
    target_hash   TEXT    NOT NULL,
    baseline_ms   REAL    NOT NULL,
    triggered_ms  REAL    NOT NULL,
    was_confirmed INTEGER NOT NULL CHECK(was_confirmed IN (0, 1)),
    scan_id       INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    observed_at   REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS priors_snapshot (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    prior_key       TEXT    NOT NULL UNIQUE,
    tool            TEXT    NOT NULL,
    value_mean      REAL    NOT NULL,
    value_std       REAL,
    n_samples       REAL    NOT NULL,
    regime          TEXT    NOT NULL CHECK(regime IN ('static', 'warmstart', 'dynamic')),
    static_fallback REAL    NOT NULL,
    updated_at      REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_registry_tool_target
    ON scan_registry(tool, target_hash);
CREATE INDEX IF NOT EXISTS idx_timing_baselines_target_cdn
    ON timing_baselines(target_hash, cdn_type);
CREATE INDEX IF NOT EXISTS idx_technique_outcomes_tech_stack
    ON technique_outcomes(technique_id, stack_signature);
CREATE INDEX IF NOT EXISTS idx_priors_snapshot_key
    ON priors_snapshot(prior_key);

CREATE TABLE IF NOT EXISTS anomaly_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER REFERENCES scan_registry(id) ON DELETE CASCADE,
    anomaly_type    TEXT    NOT NULL,
    was_flagged     INTEGER NOT NULL CHECK(was_flagged IN (0, 1)),
    stack_sig       TEXT    NOT NULL,
    magnitude       REAL,
    observed_at     REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anomaly_obs_type_stack
    ON anomaly_observations(anomaly_type, stack_sig, was_flagged);
"""

_SCHEMA_VERSION = 1


# ===========================================================================
# Classe principale
# ===========================================================================

class LearningDB:
    """
    Interfaccia al database SQLite di learning adattivo.

    Flusso per ogni scan:
      1. record_scan()     → scan_id
      2. record_*()        → osservazioni durante lo scan
      3. _update_scan_outcome() → aggiorna record finale
      4. update_priors()   → ricalcola priors_snapshot (background thread)

    I tool leggono esclusivamente da get_prior() — zero overhead a runtime
    perché legge da priors_snapshot (già calcolato, non fa aggregazioni).
    """

    DB_PATH = Path.home() / '.application_traceroute' / 'learning.db'

    # Soglie di regime per tipo di dato (n_weighted, non COUNT(*))
    REGIME_THRESHOLDS: dict = {
        'timing_baselines':     {'warmstart': 10,  'dynamic': 20},
        'technique_outcomes':   {'warmstart': 25,  'dynamic': 50},
        'evidence_weights':     {'warmstart': 20,  'dynamic': 40},
        'bypassability_scores': {'warmstart': 20,  'dynamic': 40},
        'vuln_test_limits':     {'warmstart': 15,  'dynamic': 30},
        'timing_thresholds':    {'warmstart': 10,  'dynamic': 25},
        'anomaly_observations': {'warmstart': 15,  'dynamic': 40},
    }

    def __init__(self):
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.DB_PATH),
            check_same_thread=False,   # thread daemon post-scan
            timeout=10,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA foreign_keys=ON')
        self._apply_schema()

    # ------------------------------------------------------------------
    # Schema e versioning
    # ------------------------------------------------------------------

    def _apply_schema(self):
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)
            row = self._conn.execute(
                'SELECT MAX(version) as v FROM schema_version'
            ).fetchone()
            current_version = row['v'] if row and row['v'] is not None else 0
            if current_version < _SCHEMA_VERSION:
                self._conn.execute(
                    'INSERT INTO schema_version (version, applied_at) VALUES (?, ?)',
                    (_SCHEMA_VERSION, time.time())
                )

    # ------------------------------------------------------------------
    # API pubblica — lettura prior
    # ------------------------------------------------------------------

    def get_prior(self, prior_key: str, static_fallback: float) -> float:
        """
        Ritorna valore da priors_snapshot se disponibile e regime != 'static',
        altrimenti il fallback statico.
        Zero overhead: legge da snapshot pre-calcolato.
        """
        try:
            row = self._conn.execute(
                'SELECT value_mean, regime FROM priors_snapshot WHERE prior_key = ?',
                (prior_key,)
            ).fetchone()
            if row and row['regime'] != 'static':
                return float(row['value_mean'])
        except Exception as exc:
            logger.debug("get_prior(%s) fallback: %s", prior_key, exc)
        return static_fallback

    # ------------------------------------------------------------------
    # API pubblica — scrittura osservazioni
    # ------------------------------------------------------------------

    def record_scan(self, tool: str, target: str,
                    stack_signature: Optional[str] = None,
                    outcome_summary: Optional[dict] = None) -> int:
        """Registra un nuovo scan, ritorna scan_id."""
        netloc = urlparse(target).netloc
        target_hash = hashlib.sha256(netloc.encode()).hexdigest()[:16]
        outcome_json = json.dumps(outcome_summary) if outcome_summary else None
        with self._conn:
            cur = self._conn.execute(
                '''INSERT INTO scan_registry
                   (tool, target_hash, target_domain, scan_ts,
                    stack_signature, outcome_summary)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (tool, target_hash, netloc, time.time(),
                 stack_signature, outcome_json)
            )
        return cur.lastrowid

    def _update_scan_outcome(self, scan_id: int,
                              stack_signature: Optional[str],
                              outcome_summary: Optional[dict]):
        """Aggiorna stack_signature e outcome_summary a fine scan."""
        outcome_json = json.dumps(outcome_summary) if outcome_summary else None
        duration = None
        row = self._conn.execute(
            'SELECT scan_ts FROM scan_registry WHERE id = ?', (scan_id,)
        ).fetchone()
        if row:
            duration = time.time() - row['scan_ts']
        with self._conn:
            self._conn.execute(
                '''UPDATE scan_registry
                   SET stack_signature = ?, outcome_summary = ?,
                       scan_duration_s = ?
                   WHERE id = ?''',
                (stack_signature, outcome_json, duration, scan_id)
            )

    def record_timing(self, scan_id: int, target: str, cdn_type: str,
                      tool: str, latency_ms: float):
        target_hash = _hash_target(target)
        with self._conn:
            self._conn.execute(
                '''INSERT INTO timing_baselines
                   (target_hash, cdn_type, tool, latency_ms, scan_id, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (target_hash, cdn_type, tool, latency_ms, scan_id, time.time())
            )

    def record_technique_outcome(self, scan_id: int, technique_id: str,
                                  stack_sig: str, success: bool,
                                  detected: bool = False):
        with self._conn:
            self._conn.execute(
                '''INSERT INTO technique_outcomes
                   (technique_id, tool, stack_signature, success,
                    detected, scan_id, observed_at)
                   VALUES (?, 'traceroute', ?, ?, ?, ?, ?)''',
                (technique_id, stack_sig, int(success),
                 int(detected), scan_id, time.time())
            )

    def record_evidence_weight(self, scan_id: Optional[int], evidence_type: str,
                                tool: str, lr: float, true_positive: bool,
                                context: Optional[str] = None):
        with self._conn:
            self._conn.execute(
                '''INSERT INTO evidence_weights
                   (evidence_type, tool, context, likelihood_ratio,
                    was_true_positive, scan_id, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (evidence_type, tool, context, lr,
                 int(true_positive), scan_id, time.time())
            )

    def record_bypassability(self, scan_id: int, error_type: str,
                              stack_sig: str, bypassed: bool):
        with self._conn:
            self._conn.execute(
                '''INSERT INTO bypassability_scores
                   (error_type, stack_signature, actual_bypassed,
                    scan_id, observed_at)
                   VALUES (?, ?, ?, ?, ?)''',
                (error_type, stack_sig, int(bypassed), scan_id, time.time())
            )

    def record_vuln_test(self, scan_id: int, vuln_type: str, target: str,
                          tests_run: int, true_positives: int):
        target_hash = _hash_target(target)
        with self._conn:
            self._conn.execute(
                '''INSERT INTO vuln_test_limits
                   (vuln_type, target_hash, tests_run, true_positives,
                    scan_id, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (vuln_type, target_hash, tests_run, true_positives,
                 scan_id, time.time())
            )

    def record_timing_threshold(self, scan_id: int, threshold_id: str,
                                  tool: str, target: str, baseline_ms: float,
                                  triggered_ms: float, confirmed: bool):
        target_hash = _hash_target(target)
        with self._conn:
            self._conn.execute(
                '''INSERT INTO timing_thresholds
                   (threshold_id, tool, target_hash, baseline_ms,
                    triggered_ms, was_confirmed, scan_id, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (threshold_id, tool, target_hash, baseline_ms,
                 triggered_ms, int(confirmed), scan_id, time.time())
            )

    def record_anomaly_observation(self, scan_id: int, anomaly_type: str,
                                    was_flagged: bool, stack_sig: str,
                                    magnitude: Optional[float] = None):
        """
        Registra se un tipo di anomalia è stato rilevato durante l'analisi
        differenziale di una risposta bypass.

        Usato da _update_lr_scalars() per calcolare empiricamente:
          LR(anomaly_type | stack_sig) =
              P(bypass_success | anomaly_flagged) /
              P(bypass_success | anomaly_not_flagged)

        magnitude: valore numerico dell'anomalia (es. delta size in %)
                   opzionale — utile per debug ma non usato nel calcolo LR.
        """
        with self._conn:
            self._conn.execute(
                '''INSERT INTO anomaly_observations
                   (scan_id, anomaly_type, was_flagged, stack_sig,
                    magnitude, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (scan_id, anomaly_type, int(was_flagged), stack_sig,
                 magnitude, time.time())
            )

    # ------------------------------------------------------------------
    # Processo post-scan — update_priors
    # ------------------------------------------------------------------

    def update_priors(self, tool: str, target_hash: str):
        """
        Ricalcola e aggiorna priors_snapshot per tool e target.
        Chiamato in background thread (daemon) al termine di ogni scan.
        Non blocca l'uscita del processo principale.
        """
        try:
            self._update_timing_baselines(tool, target_hash)
            self._update_technique_outcomes(tool, target_hash)
            self._update_evidence_weights(tool, target_hash)
            self._update_bypassability_scores(target_hash)
            self._update_vuln_test_limits(tool, target_hash)
            self._update_timing_thresholds(tool, target_hash)
            self._update_lr_scalars(tool, target_hash)
        except Exception as exc:
            logger.warning("update_priors(%s, %s) errore: %s", tool, target_hash, exc)

    # ------------------------------------------------------------------
    # Helper interni — weighting e regime
    # ------------------------------------------------------------------

    def _calculate_weight(self, target_hash_obs: str,
                           target_hash_current: str,
                           observed_at: float) -> float:
        """
        Peso composito: similarità target × decay temporale.

        target_similarity: 1.0 stesso target, 0.3 target diverso
        time_decay: exp(-0.03 × age_days)
        λ=0.03 → dimezza in ~23 giorni (appropriato per WAF che cambiano
        configurazione frequentemente in contesto security testing).
        """
        target_weight = 1.0 if target_hash_obs == target_hash_current else 0.3
        age_days = (time.time() - observed_at) / 86400.0
        time_decay = math.exp(-0.03 * age_days)
        return target_weight * time_decay

    def _calculate_n_weighted(self, weights: list) -> float:
        """
        n_weighted = Σ pesi di tutti i record rilevanti.
        NON è COUNT(*): un target testato 5 volte (peso 1.0) vale 5.0;
        10 target diversi (peso 0.3) valgono 3.0.
        Il regime si basa su n_weighted, non su COUNT(*).
        """
        return sum(weights)

    def _get_regime(self, data_type: str, n_weighted: float) -> str:
        thresholds = self.REGIME_THRESHOLDS[data_type]
        if n_weighted < thresholds['warmstart']:
            return 'static'
        elif n_weighted < thresholds['dynamic']:
            return 'warmstart'
        else:
            return 'dynamic'

    def _weighted_mean(self, values: list, weights: list) -> float:
        """Media pesata — usare sempre questa, mai media semplice."""
        total_weight = sum(weights)
        if total_weight == 0.0:
            return 0.0
        return sum(v * w for v, w in zip(values, weights)) / total_weight

    def _weighted_std(self, values: list, weights: list, mean: float) -> float:
        """Deviazione standard pesata."""
        total_weight = sum(weights)
        if total_weight == 0.0 or len(values) < 2:
            return 0.0
        variance = (
            sum(w * (v - mean) ** 2 for v, w in zip(values, weights))
            / total_weight
        )
        return math.sqrt(variance)

    def _blend_value(self, dynamic_mean: float, static_fallback: float,
                      regime: str, n_weighted: float, thresholds: dict) -> float:
        """
        Interpolazione lineare tra static e dynamic in regime warmstart.
        In regime static ritorna il fallback; in dynamic il valore empirico.
        """
        if regime == 'static':
            return static_fallback
        elif regime == 'dynamic':
            return dynamic_mean
        else:  # warmstart
            progress = (
                (n_weighted - thresholds['warmstart'])
                / (thresholds['dynamic'] - thresholds['warmstart'])
            )
            return static_fallback + progress * (dynamic_mean - static_fallback)

    def _regression_check(self, new_value: float, static_fallback: float,
                            score_fn, *score_args) -> float:
        """
        Se il nuovo valore produce uno score peggiore del fallback statico,
        ritorna il fallback per quel tipo di prior specifico.
        score_fn e score_args sono specifici per ogni tabella.
        """
        try:
            score_new = score_fn(new_value, *score_args)
            score_static = score_fn(static_fallback, *score_args)
            if score_new < score_static:
                return static_fallback
        except Exception:
            pass
        return new_value

    def _upsert_prior(self, prior_key: str, tool: str, value_mean: float,
                       value_std: Optional[float], n_samples: float,
                       regime: str, static_fallback: float):
        """INSERT OR REPLACE in priors_snapshot."""
        with self._conn:
            self._conn.execute(
                '''INSERT INTO priors_snapshot
                   (prior_key, tool, value_mean, value_std, n_samples,
                    regime, static_fallback, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(prior_key) DO UPDATE SET
                       value_mean      = excluded.value_mean,
                       value_std       = excluded.value_std,
                       n_samples       = excluded.n_samples,
                       regime          = excluded.regime,
                       static_fallback = excluded.static_fallback,
                       updated_at      = excluded.updated_at''',
                (prior_key, tool, value_mean, value_std, n_samples,
                 regime, static_fallback, time.time())
            )

    def _query(self, sql: str, params: tuple) -> list:
        """Esegue query e ritorna lista di Row objects."""
        return self._conn.execute(sql, params).fetchall()

    # ------------------------------------------------------------------
    # Aggiornamento per tipo di dato
    # ------------------------------------------------------------------

    def _update_timing_baselines(self, tool: str, target_hash: str):
        """
        Aggiorna prior latency_ms e latency_std per ogni cdn_type.
        Il regression check non si applica alla media di latenza (non ha
        ground truth diretto); si applica solo ai threshold decisionali.
        """
        cdn_types = set(
            row['cdn_type'] for row in self._query(
                'SELECT DISTINCT cdn_type FROM timing_baselines WHERE tool = ?',
                (tool,)
            )
        )
        thresholds = self.REGIME_THRESHOLDS['timing_baselines']

        for cdn_type in cdn_types:
            rows = self._query(
                '''SELECT latency_ms, target_hash, observed_at
                   FROM timing_baselines
                   WHERE tool = ? AND cdn_type = ?
                   ORDER BY observed_at DESC
                   LIMIT 200''',
                (tool, cdn_type)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('timing_baselines', n_weighted)

            latencies = [r['latency_ms'] for r in rows]
            dynamic_mean = self._weighted_mean(latencies, weights)
            dynamic_std = self._weighted_std(latencies, weights, dynamic_mean)

            static_fallback = _STATIC_TIMING.get(cdn_type, _STATIC_TIMING['generic'])
            static_mean = float(static_fallback['avg_ms'])
            static_std = float(static_fallback['jitter'])

            blended_mean = self._blend_value(
                dynamic_mean, static_mean, regime, n_weighted, thresholds
            )
            blended_std = self._blend_value(
                dynamic_std, static_std, regime, n_weighted, thresholds
            )

            self._upsert_prior(
                f'{tool}.cdn.{cdn_type}.latency_ms',
                tool, blended_mean, blended_std, n_weighted, regime, static_mean
            )
            self._upsert_prior(
                f'{tool}.cdn.{cdn_type}.latency_std',
                tool, blended_std, None, n_weighted, regime, static_std
            )

    def _update_technique_outcomes(self, tool: str, target_hash: str):
        """
        Aggiorna success_probability e detection_risk per ogni (technique_id, stack_sig).
        Regression check: il nuovo success_rate è migliore dello static?
        score_fn = successes_weighted / total_weighted.
        """
        thresholds = self.REGIME_THRESHOLDS['technique_outcomes']
        pairs = set(
            (row['technique_id'], row['stack_signature'])
            for row in self._query(
                '''SELECT DISTINCT technique_id, stack_signature
                   FROM technique_outcomes WHERE tool = ?''',
                (tool,)
            )
        )

        for technique_id, stack_sig in pairs:
            rows = self._query(
                '''SELECT tc.success, tc.detected, sr.target_hash, tc.observed_at
                   FROM technique_outcomes tc
                   JOIN scan_registry sr ON tc.scan_id = sr.id
                   WHERE tc.technique_id = ? AND tc.stack_signature = ?
                   ORDER BY tc.observed_at DESC
                   LIMIT 200''',
                (technique_id, stack_sig)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('technique_outcomes', n_weighted)

            successes = [float(r['success']) for r in rows]
            detections = [float(r['detected']) for r in rows]

            success_rate_dynamic = self._weighted_mean(successes, weights)
            detection_rate_dynamic = self._weighted_mean(detections, weights)

            static_priors = _STATIC_TECHNIQUE_PRIORS.get(
                technique_id, {'success_probability': 0.20, 'detection_risk': 0.15}
            )
            static_sp = static_priors['success_probability']
            static_dr = static_priors['detection_risk']

            blended_sp = self._blend_value(
                success_rate_dynamic, static_sp, regime, n_weighted, thresholds
            )
            blended_dr = self._blend_value(
                detection_rate_dynamic, static_dr, regime, n_weighted, thresholds
            )

            # Regression check success_probability
            successes_w = sum(s * w for s, w in zip(successes, weights))
            total_w = sum(weights)
            score_fn_technique = lambda v, sw, tw: sw / max(tw, 1e-9)  # noqa: E731

            final_sp = self._regression_check(
                blended_sp, static_sp, score_fn_technique, successes_w, total_w
            )
            detections_w = sum(d * w for d, w in zip(detections, weights))
            final_dr = self._regression_check(
                blended_dr, static_dr, score_fn_technique, detections_w, total_w
            )

            self._upsert_prior(
                f'traceroute.technique.{technique_id}.{stack_sig}.success_prob',
                'traceroute', final_sp, None, n_weighted, regime, static_sp
            )
            self._upsert_prior(
                f'traceroute.technique.{technique_id}.{stack_sig}.detection_risk',
                'traceroute', final_dr, None, n_weighted, regime, static_dr
            )

    def _update_evidence_weights(self, tool: str, target_hash: str):
        """
        Aggiorna likelihood ratios per ogni (evidence_type, context).
        Regression check: precision dei veri positivi.
        """
        thresholds = self.REGIME_THRESHOLDS['evidence_weights']
        pairs = set(
            (row['evidence_type'], row['context'])
            for row in self._query(
                'SELECT DISTINCT evidence_type, context FROM evidence_weights WHERE tool = ?',
                (tool,)
            )
        )

        for evidence_type, context in pairs:
            rows = self._query(
                '''SELECT ew.likelihood_ratio, ew.was_true_positive,
                          sr.target_hash, ew.observed_at
                   FROM evidence_weights ew
                   JOIN scan_registry sr ON ew.scan_id = sr.id
                   WHERE ew.evidence_type = ? AND ew.tool = ?
                     AND (ew.context = ? OR (ew.context IS NULL AND ? IS NULL))
                   ORDER BY ew.observed_at DESC
                   LIMIT 200''',
                (evidence_type, tool, context, context)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('evidence_weights', n_weighted)

            lrs = [r['likelihood_ratio'] for r in rows]
            dynamic_lr = self._weighted_mean(lrs, weights)
            dynamic_std = self._weighted_std(lrs, weights, dynamic_lr)

            # Static fallback: media dei LR hardcodati (approssimazione conservativa)
            static_lr = 2.0

            blended_lr = self._blend_value(
                dynamic_lr, static_lr, regime, n_weighted, thresholds
            )

            ctx_key = context or 'none'
            self._upsert_prior(
                f'{tool}.evidence.{evidence_type}.{ctx_key}.lr',
                tool, blended_lr, dynamic_std, n_weighted, regime, static_lr
            )

    def _update_bypassability_scores(self, target_hash: str):
        """
        Aggiorna bypassability ceiling per (error_type, stack_sig).
        Regression check: Brier score negato (calibrazione probabilistica).
        """
        thresholds = self.REGIME_THRESHOLDS['bypassability_scores']
        _STATIC_CEILING = {
            'waf_block':   0.70,
            'authz_error': 0.65,
            'rate_limit':  0.40,
            'ip_ban':      0.20,
            'captcha':     0.10,
        }

        pairs = set(
            (row['error_type'], row['stack_signature'])
            for row in self._query(
                'SELECT DISTINCT error_type, stack_signature FROM bypassability_scores',
                ()
            )
        )

        for error_type, stack_sig in pairs:
            rows = self._query(
                '''SELECT bs.actual_bypassed, sr.target_hash, bs.observed_at
                   FROM bypassability_scores bs
                   JOIN scan_registry sr ON bs.scan_id = sr.id
                   WHERE bs.error_type = ? AND bs.stack_signature = ?
                   ORDER BY bs.observed_at DESC
                   LIMIT 200''',
                (error_type, stack_sig)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('bypassability_scores', n_weighted)

            outcomes = [float(r['actual_bypassed']) for r in rows]
            dynamic_ceiling = self._weighted_mean(outcomes, weights)

            static_ceiling = _STATIC_CEILING.get(error_type, 0.50)
            blended = self._blend_value(
                dynamic_ceiling, static_ceiling, regime, n_weighted, thresholds
            )

            # Regression check: Brier score negato — più alto = meglio calibrato
            score_fn_brier = lambda v, acts: (  # noqa: E731
                -sum((v - a) ** 2 for a in acts) / max(len(acts), 1)
            )
            final_ceiling = self._regression_check(
                blended, static_ceiling, score_fn_brier, outcomes
            )

            self._upsert_prior(
                f'traceroute.bypassability.{error_type}.{stack_sig}',
                'traceroute', final_ceiling, None, n_weighted, regime, static_ceiling
            )

    def _update_vuln_test_limits(self, tool: str, target_hash: str):
        """
        Aggiorna limiti test per (vuln_type, target).
        Regression check: precision = true_positives / tests_run.
        """
        thresholds = self.REGIME_THRESHOLDS['vuln_test_limits']
        _STATIC_LIMITS = {
            'sqli': 20, 'xss': 25, 'rce': 15, 'lfi': 20,
            'ssti': 15, 'redirect': 20, 'default': 20,
        }

        vuln_types = set(
            row['vuln_type'] for row in self._query(
                'SELECT DISTINCT vuln_type FROM vuln_test_limits', ()
            )
        )

        for vuln_type in vuln_types:
            rows = self._query(
                '''SELECT vtl.tests_run, vtl.true_positives,
                          vtl.target_hash, vtl.observed_at
                   FROM vuln_test_limits vtl
                   WHERE vtl.vuln_type = ?
                   ORDER BY vtl.observed_at DESC
                   LIMIT 200''',
                (vuln_type,)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('vuln_test_limits', n_weighted)

            tests_run = [float(r['tests_run']) for r in rows]
            true_pos = [float(r['true_positives']) for r in rows]

            dynamic_limit = self._weighted_mean(tests_run, weights)
            static_limit = float(_STATIC_LIMITS.get(vuln_type, _STATIC_LIMITS['default']))

            blended = self._blend_value(
                dynamic_limit, static_limit, regime, n_weighted, thresholds
            )

            # Regression check: precision
            tp_w = sum(tp * w for tp, w in zip(true_pos, weights))
            total_w = sum(weights)
            score_fn_precision = lambda v, tw, tpw: tpw / max(tw, 1e-9)  # noqa: E731

            final_limit = self._regression_check(
                blended, static_limit, score_fn_precision, total_w, tp_w
            )

            self._upsert_prior(
                f'{tool}.vuln_limit.{vuln_type}.{target_hash}',
                tool, final_limit, None, n_weighted, regime, static_limit
            )

    def _update_timing_thresholds(self, tool: str, target_hash: str):
        """
        Aggiorna threshold temporali per (threshold_id, tool, target).
        Regression check: tasso di veri positivi al threshold v.
        """
        thresholds = self.REGIME_THRESHOLDS['timing_thresholds']
        _STATIC_THRESHOLDS = {
            'sqli_sleep':  4000.0,  # ms
            'rce_sleep':   4000.0,
            'behavioral':  1500.0,
        }

        pairs = set(
            (row['threshold_id'], row['target_hash'])
            for row in self._query(
                'SELECT DISTINCT threshold_id, target_hash FROM timing_thresholds WHERE tool = ?',
                (tool,)
            )
        )

        for threshold_id, t_hash in pairs:
            rows = self._query(
                '''SELECT baseline_ms, triggered_ms, was_confirmed, target_hash, observed_at
                   FROM timing_thresholds
                   WHERE threshold_id = ? AND tool = ? AND target_hash = ?
                   ORDER BY observed_at DESC
                   LIMIT 200''',
                (threshold_id, tool, t_hash)
            )
            if not rows:
                continue

            weights = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows
            ]
            n_weighted = self._calculate_n_weighted(weights)
            regime = self._get_regime('timing_thresholds', n_weighted)

            # Delta: triggered - baseline (differenza utile per stabilire threshold)
            deltas = [r['triggered_ms'] - r['baseline_ms'] for r in rows]
            confirmed = [float(r['was_confirmed']) for r in rows]

            dynamic_threshold = self._weighted_mean(deltas, weights)
            static_threshold = float(
                _STATIC_THRESHOLDS.get(threshold_id, 4000.0)
            )

            blended = self._blend_value(
                dynamic_threshold, static_threshold, regime, n_weighted, thresholds
            )

            # Regression check: tasso veri positivi al threshold v
            def score_fn_timing(v, conf, delt):
                hits = sum(
                    1 for c, d in zip(conf, delt) if c == 1.0 and d > v
                )
                return hits / max(len(conf), 1)

            final_threshold = self._regression_check(
                blended, static_threshold, score_fn_timing, confirmed, deltas
            )

            self._upsert_prior(
                f'{tool}.timing.{threshold_id}.{t_hash}',
                tool, final_threshold, None, n_weighted, regime, static_threshold
            )

    def _update_lr_scalars(self, tool: str, target_hash: str):
        """
        Aggiorna LR scalars per (anomaly_type, stack_sig) basandosi su
        osservazioni empiriche raccolte da record_anomaly_observation().

        Teoria: il LR scalar è il rapporto di Bayes che risponde a
        "quanto questo tipo di anomalia aumenta la probabilità che esista
        un bypass reale?"

          LR_empirico = P(bypass_success | anomaly_flagged)
                      / P(bypass_success | anomaly_not_flagged)

        Join tra anomaly_observations e technique_outcomes (via scan_id):
        per ogni scan dove questa anomalia era flagged, controlliamo se
        almeno una tecnica di bypass ha avuto successo.

        Soglie regime: warmstart=15, dynamic=40 osservazioni pesate.
        LR clamped [0.5, 50] per evitare degenerazione in assenza di dati.
        Regression check: il nuovo LR migliora il discriminability score?
        """
        regime_thresholds = self.REGIME_THRESHOLDS['anomaly_observations']

        pairs = set(
            (row['anomaly_type'], row['stack_sig'])
            for row in self._query(
                'SELECT DISTINCT anomaly_type, stack_sig FROM anomaly_observations',
                ()
            )
        )
        if not pairs:
            return

        for anomaly_type, stack_sig in pairs:
            static_lr = _STATIC_LR_SCALARS.get(anomaly_type, 5.0)

            # Scans dove l'anomalia era flagged — verifica bypass success
            rows_flagged = self._query(
                '''SELECT ao.scan_id, sr.target_hash, ao.observed_at,
                          COALESCE(MAX(tc.success), 0) AS any_success
                   FROM anomaly_observations ao
                   JOIN scan_registry sr ON ao.scan_id = sr.id
                   LEFT JOIN technique_outcomes tc ON tc.scan_id = ao.scan_id
                   WHERE ao.anomaly_type = ? AND ao.stack_sig = ? AND ao.was_flagged = 1
                   GROUP BY ao.scan_id, sr.target_hash, ao.observed_at
                   ORDER BY ao.observed_at DESC
                   LIMIT 200''',
                (anomaly_type, stack_sig)
            )

            # Scans dove l'anomalia NON era flagged (controfattuale)
            rows_not_flagged = self._query(
                '''SELECT ao.scan_id, sr.target_hash, ao.observed_at,
                          COALESCE(MAX(tc.success), 0) AS any_success
                   FROM anomaly_observations ao
                   JOIN scan_registry sr ON ao.scan_id = sr.id
                   LEFT JOIN technique_outcomes tc ON tc.scan_id = ao.scan_id
                   WHERE ao.anomaly_type = ? AND ao.stack_sig = ? AND ao.was_flagged = 0
                   GROUP BY ao.scan_id, sr.target_hash, ao.observed_at
                   ORDER BY ao.observed_at DESC
                   LIMIT 200''',
                (anomaly_type, stack_sig)
            )

            if not rows_flagged:
                continue

            weights_flagged = [
                self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                for r in rows_flagged
            ]
            n_weighted = self._calculate_n_weighted(weights_flagged)
            regime = self._get_regime('anomaly_observations', n_weighted)

            p_success_flagged = self._weighted_mean(
                [float(r['any_success']) for r in rows_flagged],
                weights_flagged
            )

            if rows_not_flagged:
                weights_not_flagged = [
                    self._calculate_weight(r['target_hash'], target_hash, r['observed_at'])
                    for r in rows_not_flagged
                ]
                p_success_not_flagged = self._weighted_mean(
                    [float(r['any_success']) for r in rows_not_flagged],
                    weights_not_flagged
                )
            else:
                # Prior neutro se non abbiamo controfattuali
                p_success_not_flagged = 0.10

            # LR empirico — clamp per stabilità numerica
            lr_empirical = p_success_flagged / max(p_success_not_flagged, 0.05)
            lr_empirical = max(0.5, min(50.0, lr_empirical))

            blended_lr = self._blend_value(
                lr_empirical, static_lr, regime, n_weighted, regime_thresholds
            )

            # Regression check: discriminability = P(flagged|success) - P(flagged|fail)
            # Un LR migliore discrimina meglio i bypass reali dai falsi allarmi.
            def _discriminability(lr_val: float, pf: float, pnf: float) -> float:
                return (lr_val * pnf - pnf) / max(lr_val * pnf + pnf, 1e-9)

            final_lr = self._regression_check(
                blended_lr, static_lr, _discriminability,
                p_success_flagged, p_success_not_flagged
            )

            self._upsert_prior(
                f'traceroute.lr_scalar.{anomaly_type}.{stack_sig}',
                'traceroute', final_lr, None, n_weighted, regime, static_lr
            )
