/* CVSS calculator helper for the advisory edit form.
 *
 * Hangs off each `data-severity-row` in the severity formset. The free-text
 * `data-severity-score="cvss"` input remains the canonical store of the
 * vector string; this module renders a derived view (collapsible per-row
 * `<details>` with one fieldset per metric group) plus a live score badge
 * (`output[data-cvss-score]`) rendered next to the input.
 *
 * Key UX rule: switching the CVSS version dropdown does NOT erase the
 * metrics already entered for the other versions. Per-row state keeps an
 * independent bucket for v2, v3.1 and v4.0; the active bucket is mirrored
 * into the score input.
 *
 * Scoring:
 *   - v2 / v3.1: standard FIRST.org formulas, full Base + Temporal.
 *   - v4.0:      FIRST.org Base + Threat. Implementation uses the official
 *                MacroVector lookup table plus the per-EQ severity-distance
 *                interpolation from the v4.0 spec §7. Environmental and
 *                Supplemental metrics are out of scope and treated as
 *                Not-Defined throughout.
 *
 * Spec references:
 *   - CVSS v2.0: https://www.first.org/cvss/v2/guide
 *   - CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
 *   - CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Metric catalogues
  // ---------------------------------------------------------------------------
  //
  // Each entry: {group, id, label, description, values: [{id, label, description}]}
  // Order matters: it is the order metrics appear in the canonical vector
  // string and in the rendered UI.

  var METRICS_V2 = [
    {
      group: "Base", id: "AV", label: "Attack Vector",
      description: "How the vulnerability is exploited.",
      values: [
        { id: "N", label: "Network", description: "Remotely exploitable across a network." },
        { id: "A", label: "Adjacent", description: "Bound to the same local network or collision domain." },
        { id: "L", label: "Local", description: "Requires local access, e.g. a shell or session." },
      ],
    },
    {
      group: "Base", id: "AC", label: "Access Complexity",
      description: "Complexity of the attack required to exploit.",
      values: [
        { id: "L", label: "Low", description: "No special conditions; access can be reliably obtained." },
        { id: "M", label: "Medium", description: "Some specialized conditions exist." },
        { id: "H", label: "High", description: "Specialized conditions; difficult to exploit." },
      ],
    },
    {
      group: "Base", id: "Au", label: "Authentication",
      description: "Times an attacker must authenticate to exploit.",
      values: [
        { id: "N", label: "None", description: "No authentication required." },
        { id: "S", label: "Single", description: "One instance of authentication required." },
        { id: "M", label: "Multiple", description: "Two or more authentications required." },
      ],
    },
    {
      group: "Base", id: "C", label: "Confidentiality Impact",
      description: "Impact on confidentiality if exploited.",
      values: [
        { id: "N", label: "None", description: "No impact." },
        { id: "P", label: "Partial", description: "Some access to information." },
        { id: "C", label: "Complete", description: "Total information disclosure." },
      ],
    },
    {
      group: "Base", id: "I", label: "Integrity Impact",
      description: "Impact on integrity if exploited.",
      values: [
        { id: "N", label: "None", description: "No impact." },
        { id: "P", label: "Partial", description: "Some modification possible." },
        { id: "C", label: "Complete", description: "Total compromise of integrity." },
      ],
    },
    {
      group: "Base", id: "A", label: "Availability Impact",
      description: "Impact on availability if exploited.",
      values: [
        { id: "N", label: "None", description: "No impact." },
        { id: "P", label: "Partial", description: "Reduced performance or interruptions." },
        { id: "C", label: "Complete", description: "Total shutdown of the affected resource." },
      ],
    },
    {
      group: "Temporal", id: "E", label: "Exploitability",
      description: "Current state of exploit techniques.",
      values: [
        { id: "ND", label: "Not Defined", description: "Skip this metric." },
        { id: "U", label: "Unproven", description: "No exploit code available." },
        { id: "POC", label: "Proof-of-Concept", description: "Proof-of-concept exploit exists." },
        { id: "F", label: "Functional", description: "Functional exploit code is available." },
        { id: "H", label: "High", description: "Functional autonomous exploit code is widely available." },
      ],
    },
    {
      group: "Temporal", id: "RL", label: "Remediation Level",
      description: "Availability of a remediation.",
      values: [
        { id: "ND", label: "Not Defined", description: "Skip this metric." },
        { id: "OF", label: "Official Fix", description: "An official patch is available." },
        { id: "TF", label: "Temporary Fix", description: "A temporary workaround is available." },
        { id: "W", label: "Workaround", description: "An unofficial, non-vendor workaround exists." },
        { id: "U", label: "Unavailable", description: "No solution available." },
      ],
    },
    {
      group: "Temporal", id: "RC", label: "Report Confidence",
      description: "Degree of confidence in the report.",
      values: [
        { id: "ND", label: "Not Defined", description: "Skip this metric." },
        { id: "UC", label: "Unconfirmed", description: "Single unconfirmed source." },
        { id: "UR", label: "Uncorroborated", description: "Multiple non-official sources." },
        { id: "C", label: "Confirmed", description: "Acknowledged by the vendor or author." },
      ],
    },
  ];

  var METRICS_V31 = [
    {
      group: "Base", id: "AV", label: "Attack Vector",
      description: "Context by which exploitation is possible.",
      values: [
        { id: "N", label: "Network", description: "Remotely exploitable across the network." },
        { id: "A", label: "Adjacent", description: "Bound to the same physical or logical local network." },
        { id: "L", label: "Local", description: "Requires local read/write/execute capabilities." },
        { id: "P", label: "Physical", description: "Requires physical interaction with the device." },
      ],
    },
    {
      group: "Base", id: "AC", label: "Attack Complexity",
      description: "Conditions beyond the attacker's control needed to exploit.",
      values: [
        { id: "L", label: "Low", description: "No specialized access conditions; reliable." },
        { id: "H", label: "High", description: "Successful attack depends on conditions outside the attacker's control." },
      ],
    },
    {
      group: "Base", id: "PR", label: "Privileges Required",
      description: "Level of privileges an attacker must possess prior to exploitation.",
      values: [
        { id: "N", label: "None", description: "Attacker is unauthenticated." },
        { id: "L", label: "Low", description: "Basic user privileges required." },
        { id: "H", label: "High", description: "Significant (admin) privileges required." },
      ],
    },
    {
      group: "Base", id: "UI", label: "User Interaction",
      description: "Whether the attack requires user participation.",
      values: [
        { id: "N", label: "None", description: "No user interaction needed." },
        { id: "R", label: "Required", description: "Some user action is required." },
      ],
    },
    {
      group: "Base", id: "S", label: "Scope",
      description: "Whether a successful attack can affect components beyond the vulnerable one.",
      values: [
        { id: "U", label: "Unchanged", description: "Impact limited to the vulnerable component's authority." },
        { id: "C", label: "Changed", description: "Impact extends beyond the vulnerable component's authority." },
      ],
    },
    {
      group: "Base", id: "C", label: "Confidentiality Impact",
      description: "Impact on the confidentiality of information.",
      values: [
        { id: "N", label: "None", description: "No loss of confidentiality." },
        { id: "L", label: "Low", description: "Some confidentiality loss." },
        { id: "H", label: "High", description: "Total loss of confidentiality." },
      ],
    },
    {
      group: "Base", id: "I", label: "Integrity Impact",
      description: "Impact on the integrity of information.",
      values: [
        { id: "N", label: "None", description: "No loss of integrity." },
        { id: "L", label: "Low", description: "Some integrity loss." },
        { id: "H", label: "High", description: "Total loss of integrity." },
      ],
    },
    {
      group: "Base", id: "A", label: "Availability Impact",
      description: "Impact on the availability of the affected component.",
      values: [
        { id: "N", label: "None", description: "No availability impact." },
        { id: "L", label: "Low", description: "Reduced performance or interruptions." },
        { id: "H", label: "High", description: "Total loss of availability." },
      ],
    },
    {
      group: "Temporal", id: "E", label: "Exploit Code Maturity",
      description: "Likelihood of the vulnerability being attacked.",
      values: [
        { id: "X", label: "Not Defined", description: "Skip this metric." },
        { id: "U", label: "Unproven", description: "No exploit code available." },
        { id: "P", label: "Proof-of-Concept", description: "Proof-of-concept exploit exists." },
        { id: "F", label: "Functional", description: "Functional exploit code is available." },
        { id: "H", label: "High", description: "Functional autonomous exploit code is widely available." },
      ],
    },
    {
      group: "Temporal", id: "RL", label: "Remediation Level",
      description: "Type of remediation available.",
      values: [
        { id: "X", label: "Not Defined", description: "Skip this metric." },
        { id: "O", label: "Official Fix", description: "An official patch is available." },
        { id: "T", label: "Temporary Fix", description: "A temporary workaround is available." },
        { id: "W", label: "Workaround", description: "An unofficial workaround exists." },
        { id: "U", label: "Unavailable", description: "No solution available." },
      ],
    },
    {
      group: "Temporal", id: "RC", label: "Report Confidence",
      description: "Confidence in the existence of the vulnerability.",
      values: [
        { id: "X", label: "Not Defined", description: "Skip this metric." },
        { id: "U", label: "Unknown", description: "Reports of impact are unverified." },
        { id: "R", label: "Reasonable", description: "Significant details have been published but root cause is not fully known." },
        { id: "C", label: "Confirmed", description: "Detailed reports exist, or reproduction confirmed." },
      ],
    },
  ];

  var METRICS_V40 = [
    {
      group: "Base", id: "AV", label: "Attack Vector",
      description: "Context by which exploitation is possible.",
      values: [
        { id: "N", label: "Network", description: "Network-reachable, no local proximity needed." },
        { id: "A", label: "Adjacent", description: "Same physical or logical adjacent network." },
        { id: "L", label: "Local", description: "Requires local access or a separate exploit chain." },
        { id: "P", label: "Physical", description: "Requires physical interaction with the device." },
      ],
    },
    {
      group: "Base", id: "AC", label: "Attack Complexity",
      description: "Measurable conditions that must hold for exploitation.",
      values: [
        { id: "L", label: "Low", description: "No specialized conditions." },
        { id: "H", label: "High", description: "Attacker must evade or work around security mechanisms." },
      ],
    },
    {
      group: "Base", id: "AT", label: "Attack Requirements",
      description: "Deployment or runtime conditions that enable the attack.",
      values: [
        { id: "N", label: "None", description: "No specific requirements." },
        { id: "P", label: "Present", description: "A specific configuration or state is required." },
      ],
    },
    {
      group: "Base", id: "PR", label: "Privileges Required",
      description: "Level of privileges needed before exploitation.",
      values: [
        { id: "N", label: "None", description: "Attacker is unauthenticated." },
        { id: "L", label: "Low", description: "Basic privileges required." },
        { id: "H", label: "High", description: "Significant (admin) privileges required." },
      ],
    },
    {
      group: "Base", id: "UI", label: "User Interaction",
      description: "Whether the attack requires user participation.",
      values: [
        { id: "N", label: "None", description: "No user interaction needed." },
        { id: "P", label: "Passive", description: "Limited interaction; user does not realize an attack is in progress." },
        { id: "A", label: "Active", description: "User must take specific deliberate actions." },
      ],
    },
    {
      group: "Base", id: "VC", label: "Vulnerable System Confidentiality",
      description: "Confidentiality impact on the vulnerable system itself.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of confidentiality." },
        { id: "L", label: "Low", description: "Limited loss of confidentiality." },
        { id: "N", label: "None", description: "No loss of confidentiality." },
      ],
    },
    {
      group: "Base", id: "VI", label: "Vulnerable System Integrity",
      description: "Integrity impact on the vulnerable system itself.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of integrity." },
        { id: "L", label: "Low", description: "Limited loss of integrity." },
        { id: "N", label: "None", description: "No loss of integrity." },
      ],
    },
    {
      group: "Base", id: "VA", label: "Vulnerable System Availability",
      description: "Availability impact on the vulnerable system itself.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of availability." },
        { id: "L", label: "Low", description: "Limited loss of availability." },
        { id: "N", label: "None", description: "No loss of availability." },
      ],
    },
    {
      group: "Base", id: "SC", label: "Subsequent System Confidentiality",
      description: "Confidentiality impact on downstream systems.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of confidentiality." },
        { id: "L", label: "Low", description: "Limited loss of confidentiality." },
        { id: "N", label: "None", description: "No loss of confidentiality." },
      ],
    },
    {
      group: "Base", id: "SI", label: "Subsequent System Integrity",
      description: "Integrity impact on downstream systems.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of integrity." },
        { id: "L", label: "Low", description: "Limited loss of integrity." },
        { id: "N", label: "None", description: "No loss of integrity." },
      ],
    },
    {
      group: "Base", id: "SA", label: "Subsequent System Availability",
      description: "Availability impact on downstream systems.",
      values: [
        { id: "H", label: "High", description: "Serious or total loss of availability." },
        { id: "L", label: "Low", description: "Limited loss of availability." },
        { id: "N", label: "None", description: "No loss of availability." },
      ],
    },
    {
      group: "Threat", id: "E", label: "Exploit Maturity",
      description: "Likelihood that the vulnerability is being attacked.",
      values: [
        { id: "X", label: "Not Defined", description: "Skip this metric." },
        { id: "A", label: "Attacked", description: "Active attacks observed, or exploit code widely available." },
        { id: "P", label: "Proof-of-Concept", description: "Proof-of-concept exploit exists but no observed attacks." },
        { id: "U", label: "Unreported", description: "No proof-of-concept exploit known to exist." },
      ],
    },
  ];

  var VERSIONS = {
    "CVSS_V2": { id: "v2", label: "v2", prefix: "", metrics: METRICS_V2 },
    "CVSS_V3": { id: "v3.1", label: "v3.1", prefix: "CVSS:3.1/", metrics: METRICS_V31 },
    "CVSS_V4": { id: "v4.0", label: "v4.0", prefix: "CVSS:4.0/", metrics: METRICS_V40 },
  };

  // Reverse map: internal versionId → the OSV severity.type string that the
  // form's <select data-severity-type> uses. Needed for paste auto-detection
  // when we have to programmatically swap the dropdown.
  var ID_TO_TYPE = { "v2": "CVSS_V2", "v3.1": "CVSS_V3", "v4.0": "CVSS_V4" };

  function metricCatalogue(versionId) {
    if (versionId === "v2") return METRICS_V2;
    if (versionId === "v3.1") return METRICS_V31;
    return METRICS_V40;
  }

  // ---------------------------------------------------------------------------
  // Parsers and builders
  // ---------------------------------------------------------------------------

  function parseVector(versionId, vec) {
    var out = {};
    if (!vec) return out;
    var s = String(vec).trim();
    // Strip the version prefix if present; leave the slash-separated metric pairs.
    if (versionId === "v3.1" && /^CVSS:3\.\d\//i.test(s)) {
      s = s.replace(/^CVSS:3\.\d\//i, "");
    } else if (versionId === "v4.0" && /^CVSS:4\.\d\//i.test(s)) {
      s = s.replace(/^CVSS:4\.\d\//i, "");
    } else if (versionId === "v2") {
      // v2 has no version prefix in OSV; leave as-is.
    }
    var validIds = {};
    metricCatalogue(versionId).forEach(function (m) {
      validIds[m.id] = {};
      m.values.forEach(function (v) { validIds[m.id][v.id] = true; });
    });
    s.split("/").forEach(function (pair) {
      var parts = pair.split(":");
      if (parts.length !== 2) return;
      var id = parts[0];
      var val = parts[1];
      if (validIds[id] && validIds[id][val]) out[id] = val;
    });
    return out;
  }

  function buildVector(versionId, metrics) {
    var cat = metricCatalogue(versionId);
    var prefix = VERSIONS["CVSS_V2"].metrics === cat ? "" :
                 versionId === "v3.1" ? "CVSS:3.1/" : "CVSS:4.0/";
    var notDefined = { "ND": true, "X": true };
    var parts = [];
    cat.forEach(function (m) {
      var v = metrics[m.id];
      if (!v) return;
      // Suppress Not-Defined entries from the canonical string so we don't
      // emit noise like "/E:X" or "/RL:ND".
      if (m.group !== "Base" && notDefined[v]) return;
      parts.push(m.id + ":" + v);
    });
    return prefix + parts.join("/");
  }

  function hasFullBase(versionId, metrics) {
    var cat = metricCatalogue(versionId);
    for (var i = 0; i < cat.length; i++) {
      if (cat[i].group === "Base" && !metrics[cat[i].id]) return false;
    }
    return true;
  }

  // Best-guess CVSS version for a free-text string. Returns one of "v2",
  // "v3.1", "v4.0", or null when no confident guess is possible. Used by the
  // paste-into-input handler so the calculator can follow the pasted vector
  // even if the type dropdown is currently set to a different version.
  //
  //   1. An explicit `CVSS:2.x/`, `CVSS:3.x/` or `CVSS:4.x/` prefix wins —
  //      this is the OSV-canonical way to encode the version.
  //   2. Otherwise (legitimate for v2, where the prefix is optional), try
  //      parsing under each version and pick the one whose parse yields a
  //      complete base. If multiple complete bases happen to match (rare —
  //      would require all metric ids and values to overlap), prefer the
  //      version that is currently active so we don't surprise the user with
  //      a needless switch.
  //   3. Partial pastes — none of the versions yields a complete base —
  //      return null and let the caller fall back to "parse under active
  //      version" so the user can keep typing in their chosen version.
  function detectVersion(text, activeId) {
    if (!text) return null;
    var s = String(text).trim();
    if (/^CVSS:2\.\d\//i.test(s)) return "v2";
    if (/^CVSS:3\.\d\//i.test(s)) return "v3.1";
    if (/^CVSS:4\.\d\//i.test(s)) return "v4.0";
    var candidates = [];
    ["v2", "v3.1", "v4.0"].forEach(function (id) {
      if (hasFullBase(id, parseVector(id, s))) candidates.push(id);
    });
    if (candidates.length === 0) return null;
    if (candidates.length === 1) return candidates[0];
    if (activeId && candidates.indexOf(activeId) !== -1) return activeId;
    return candidates[0];
  }

  // ---------------------------------------------------------------------------
  // Score → qualitative rating
  // ---------------------------------------------------------------------------

  function severityLabel(score) {
    if (score == null) return "";
    if (score <= 0) return "None";
    if (score < 4.0) return "Low";
    if (score < 7.0) return "Medium";
    if (score < 9.0) return "High";
    return "Critical";
  }

  function severityClass(label) {
    if (!label) return "";
    return "cvss-severity-" + label.toLowerCase();
  }

  // ---------------------------------------------------------------------------
  // CVSS v2 scoring  (FIRST CVSS v2 guide §3.2)
  // ---------------------------------------------------------------------------

  var V2_AV = { N: 1.0, A: 0.646, L: 0.395 };
  var V2_AC = { L: 0.71, M: 0.61, H: 0.35 };
  var V2_Au = { N: 0.704, S: 0.56, M: 0.45 };
  var V2_CIA = { N: 0.0, P: 0.275, C: 0.660 };
  var V2_E = { U: 0.85, POC: 0.9, F: 0.95, H: 1.0, ND: 1.0 };
  var V2_RL = { OF: 0.87, TF: 0.9, W: 0.95, U: 1.0, ND: 1.0 };
  var V2_RC = { UC: 0.9, UR: 0.95, C: 1.0, ND: 1.0 };

  function scoreV2(metrics) {
    if (!hasFullBase("v2", metrics)) return null;
    var impact = 10.41 * (1 - (1 - V2_CIA[metrics.C]) * (1 - V2_CIA[metrics.I]) * (1 - V2_CIA[metrics.A]));
    var exploitability = 20 * V2_AV[metrics.AV] * V2_AC[metrics.AC] * V2_Au[metrics.Au];
    var fImpact = impact === 0 ? 0 : 1.176;
    var base = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact;
    var baseScore = round1(base);
    var e = V2_E[metrics.E || "ND"];
    var rl = V2_RL[metrics.RL || "ND"];
    var rc = V2_RC[metrics.RC || "ND"];
    var temporal = round1(baseScore * e * rl * rc);
    return { score: temporal, label: severityLabel(temporal) };
  }

  function round1(n) {
    return Math.round(n * 10) / 10;
  }

  // ---------------------------------------------------------------------------
  // CVSS v3.1 scoring  (FIRST CVSS v3.1 specification §7)
  // ---------------------------------------------------------------------------

  var V31_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  var V31_AC = { L: 0.77, H: 0.44 };
  var V31_PR_U = { N: 0.85, L: 0.62, H: 0.27 };
  var V31_PR_C = { N: 0.85, L: 0.68, H: 0.50 };
  var V31_UI = { N: 0.85, R: 0.62 };
  var V31_CIA = { N: 0.0, L: 0.22, H: 0.56 };
  var V31_E = { X: 1.0, U: 0.91, P: 0.94, F: 0.97, H: 1.0 };
  var V31_RL = { X: 1.0, O: 0.95, T: 0.96, W: 0.97, U: 1.0 };
  var V31_RC = { X: 1.0, U: 0.92, R: 0.96, C: 1.0 };

  function roundUp1(n) {
    // RoundUp1 from CVSS v3.1 spec §7. Avoids the IEEE-754 rounding pitfalls
    // by operating on a 100000x-scaled integer.
    var x = Math.round(n * 100000);
    if (x % 10000 === 0) return x / 100000;
    return (Math.floor(x / 10000) + 1) / 10;
  }

  function scoreV31(metrics) {
    if (!hasFullBase("v3.1", metrics)) return null;
    var iss = 1 - ((1 - V31_CIA[metrics.C]) * (1 - V31_CIA[metrics.I]) * (1 - V31_CIA[metrics.A]));
    var impact;
    if (metrics.S === "U") {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }
    var prTable = metrics.S === "C" ? V31_PR_C : V31_PR_U;
    var exploitability = 8.22 * V31_AV[metrics.AV] * V31_AC[metrics.AC] * prTable[metrics.PR] * V31_UI[metrics.UI];
    var base;
    if (impact <= 0) {
      base = 0;
    } else if (metrics.S === "U") {
      base = roundUp1(Math.min(impact + exploitability, 10));
    } else {
      base = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
    }
    var e = V31_E[metrics.E || "X"];
    var rl = V31_RL[metrics.RL || "X"];
    var rc = V31_RC[metrics.RC || "X"];
    var temporal = roundUp1(base * e * rl * rc);
    return { score: temporal, label: severityLabel(temporal) };
  }

  // ---------------------------------------------------------------------------
  // CVSS v4.0 scoring  (FIRST CVSS v4.0 specification §7)
  // ---------------------------------------------------------------------------
  //
  // The full v4 algorithm uses a MacroVector lookup plus per-EQ severity-
  // distance interpolation against a "highest-severity vector" representative
  // for each EQ class. Tables below are taken verbatim from the FIRST.org
  // reference calculator (MIT-licensed). Environmental and Supplemental
  // metrics are not exposed in the UI; they default to Not-Defined and are
  // handled by the spec's standard "treat as worst case" rules.

  // MacroVector → base score (eq1 eq2 eq3 eq4 eq5 eq6).
  var V40_MV = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.2, "000021": 8.9,
    "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5,
    "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
    "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
    "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
    "011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
    "011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
    "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
    "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9,
    "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 8.7, "100121": 7.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
    "110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
    "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
    "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
    "111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
    "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
    "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6, "112121": 1.5,
    "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
    "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
    "210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
    "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
    "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
    "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
    "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4, "212111": 1.2, "212121": 0.5,
    "212201": 1, "212211": 0.3, "212221": 0.1,
  };

  // Highest-severity vectors per EQ level (used to compute severity distances).
  // Each entry is the prefix of a vector that maximizes severity within the
  // given EQ class. Taken from the FIRST.org reference calculator.
  var V40_MAX_COMPOSED = {
    eq1: {
      0: ["AV:N/PR:N/UI:N/"],
      1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
      2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    eq2: {
      0: ["AC:L/AT:N/"],
      1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    eq3: {
      0: { 0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], 1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] },
      1: { 0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], 1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] },
      2: { 1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] },
    },
    eq4: {
      0: ["SC:H/SI:S/SA:S/"],
      1: ["SC:H/SI:H/SA:H/"],
      2: ["SC:L/SI:L/SA:L/"],
    },
    eq5: {
      0: ["E:A/"],
      1: ["E:P/"],
      2: ["E:U/"],
    },
    eq6: {
      0: ["CR:H/IR:H/AR:H/"],
      1: ["CR:M/IR:M/AR:M/"],
    },
  };

  var V40_MAX_SEVERITY = {
    eq1: { 0: 1, 1: 4, 2: 5 },
    eq2: { 0: 1, 1: 2 },
    eq3eq6: {
      0: { 0: 7, 1: 6 },
      1: { 0: 8, 1: 8 },
      2: { 1: 10 },
    },
    eq4: { 0: 6, 1: 5, 2: 4 },
    eq5: { 0: 1, 1: 1, 2: 1 },
  };

  // Severity weights per metric value (from the FIRST.org reference calc).
  var V40_VALUES = {
    AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
    PR: { N: 0.0, L: 0.1, H: 0.2 },
    UI: { N: 0.0, P: 0.1, A: 0.2 },
    AC: { L: 0.0, H: 0.1 },
    AT: { N: 0.0, P: 0.1 },
    VC: { H: 0.0, L: 0.1, N: 0.2 },
    VI: { H: 0.0, L: 0.1, N: 0.2 },
    VA: { H: 0.0, L: 0.1, N: 0.2 },
    SC: { H: 0.1, L: 0.2, N: 0.3 },
    SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
    SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
    CR: { H: 0.0, M: 0.1, L: 0.2 },
    IR: { H: 0.0, M: 0.1, L: 0.2 },
    AR: { H: 0.0, M: 0.1, L: 0.2 },
    E:  { U: 0.2, P: 0.1, A: 0 },
  };

  function v40Eq(metrics) {
    // Defaults for unexposed environmental/supplemental fields: Not-Defined,
    // which the v4 spec equates to the worst-case threat (E=X → A) and
    // M-rated requirements (CR/IR/AR=X → H equivalent for the EQ calc).
    var av = metrics.AV, pr = metrics.PR, ui = metrics.UI;
    var ac = metrics.AC, at = metrics.AT;
    var vc = metrics.VC, vi = metrics.VI, va = metrics.VA;
    var sc = metrics.SC, si = metrics.SI, sa = metrics.SA;
    var e = metrics.E && metrics.E !== "X" ? metrics.E : "A";
    // Environmental defaults
    var cr = "H", ir = "H", ar = "H";
    var msi = si, msa = sa;

    var eq1;
    if (av === "N" && pr === "N" && ui === "N") eq1 = 0;
    else if ((av === "N" || pr === "N" || ui === "N") && !(av === "N" && pr === "N" && ui === "N") && av !== "P") eq1 = 1;
    else eq1 = 2;

    var eq2 = (ac === "L" && at === "N") ? 0 : 1;

    var eq3;
    if (vc === "H" && vi === "H") eq3 = 0;
    else if (!(vc === "H" && vi === "H") && (vc === "H" || vi === "H" || va === "H")) eq3 = 1;
    else eq3 = 2;

    var eq4;
    if (msi === "S" || msa === "S") eq4 = 0;
    else if (!(msi === "S" || msa === "S") && (sc === "H" || si === "H" || sa === "H")) eq4 = 1;
    else eq4 = 2;

    var eq5;
    if (e === "A") eq5 = 0;
    else if (e === "P") eq5 = 1;
    else eq5 = 2;

    var eq6;
    var crVcH = cr === "H" && vc === "H";
    var irViH = ir === "H" && vi === "H";
    var arVaH = ar === "H" && va === "H";
    eq6 = (crVcH || irViH || arVaH) ? 0 : 1;

    return { eq1: eq1, eq2: eq2, eq3: eq3, eq4: eq4, eq5: eq5, eq6: eq6 };
  }

  function v40ExtractFromComposed(composed, metricId) {
    // Pull "X:Y" for metricId out of a maxComposed prefix string.
    var re = new RegExp("(?:^|/)" + metricId + ":([A-Za-z]+)(?:/|$)");
    var m = composed.match(re);
    return m ? m[1] : null;
  }

  function v40SeverityDistance(vector, maxVectors, axisMetrics) {
    // Pick the maxComposed candidate that yields the minimum non-negative
    // distance from `vector` (per the spec: pick the closest max-severity
    // vector that still strictly dominates).
    var best = null;
    for (var i = 0; i < maxVectors.length; i++) {
      var max = maxVectors[i];
      var distance = 0;
      var feasible = true;
      for (var j = 0; j < axisMetrics.length; j++) {
        var mId = axisMetrics[j];
        var maxVal = v40ExtractFromComposed(max, mId);
        var curVal = vector[mId];
        if (maxVal == null || curVal == null) continue;
        var weights = V40_VALUES[mId];
        if (!weights) continue;
        var maxW = weights[maxVal];
        var curW = weights[curVal];
        if (maxW == null || curW == null) continue;
        var d = curW - maxW;
        if (d < 0) {
          // Vector is more severe than this max — infeasible candidate.
          feasible = false; break;
        }
        distance += d;
      }
      if (feasible && (best == null || distance < best)) best = distance;
    }
    return best == null ? 0 : best;
  }

  function scoreV40(metrics) {
    if (!hasFullBase("v4.0", metrics)) return null;

    var eq = v40Eq(metrics);
    var mvKey = "" + eq.eq1 + eq.eq2 + eq.eq3 + eq.eq4 + eq.eq5 + eq.eq6;
    var value = V40_MV[mvKey];
    if (value == null) return null;

    // Higher MV index → lower severity. The "lower" macroVector along each
    // axis is the value at (eqI - 1) … wait actually per the FIRST.org calc
    // the algorithm walks (eqI + 1) along the axis (i.e., the *next less
    // severe* class) and uses the difference. Implementation follows the
    // reference calc verbatim.

    function lookupNext(axis) {
      var next = Object.assign({}, eq);
      next[axis] = eq[axis] + 1;
      var key = "" + next.eq1 + next.eq2 + next.eq3 + next.eq4 + next.eq5 + next.eq6;
      return { key: key, value: V40_MV[key] };
    }

    // Step-1: available distances per axis.
    var stepAvail = {};
    ["eq1", "eq2", "eq3", "eq4", "eq5", "eq6"].forEach(function (axis) {
      // eq3 and eq6 are coupled in the spec; treat them jointly.
      if (axis === "eq6") return;
      if (axis === "eq3") {
        var nextE3 = Object.assign({}, eq); nextE3.eq3 = eq.eq3 + 1;
        var k3 = "" + nextE3.eq1 + nextE3.eq2 + nextE3.eq3 + nextE3.eq4 + nextE3.eq5 + nextE3.eq6;
        var nextE6 = Object.assign({}, eq); nextE6.eq6 = eq.eq6 + 1;
        var k6 = "" + nextE6.eq1 + nextE6.eq2 + nextE6.eq3 + nextE6.eq4 + nextE6.eq5 + nextE6.eq6;
        var nextBoth = Object.assign({}, eq); nextBoth.eq3 += 1; nextBoth.eq6 += 1;
        var kBoth = "" + nextBoth.eq1 + nextBoth.eq2 + nextBoth.eq3 + nextBoth.eq4 + nextBoth.eq5 + nextBoth.eq6;
        var v3 = V40_MV[k3], v6 = V40_MV[k6], vBoth = V40_MV[kBoth];
        // Pick the most-favoured non-null neighbour, akin to the reference calc.
        var candidates = [v3, v6, vBoth].filter(function (x) { return x != null; });
        if (candidates.length === 0) { stepAvail.eq3eq6 = null; return; }
        var maxNext = Math.max.apply(null, candidates);
        stepAvail.eq3eq6 = value - maxNext;
        return;
      }
      var n = lookupNext(axis);
      stepAvail[axis] = n.value == null ? null : value - n.value;
    });

    // Step-2: per-axis severity distance (current vs maxComposed).
    var sevDist = {};
    sevDist.eq1 = v40SeverityDistance(metrics, V40_MAX_COMPOSED.eq1[eq.eq1] || [], ["AV", "PR", "UI"]);
    sevDist.eq2 = v40SeverityDistance(metrics, V40_MAX_COMPOSED.eq2[eq.eq2] || [], ["AC", "AT"]);
    var eq3Composed = (V40_MAX_COMPOSED.eq3[eq.eq3] || {})[eq.eq6] || [];
    sevDist.eq3eq6 = v40SeverityDistance(metrics, eq3Composed, ["VC", "VI", "VA", "CR", "IR", "AR"]);
    sevDist.eq4 = v40SeverityDistance(metrics, V40_MAX_COMPOSED.eq4[eq.eq4] || [], ["SC", "SI", "SA"]);
    sevDist.eq5 = 0; // Threat-only axis; no distance to compute.

    // Step-3: normalize by maxSeverity per axis, weight by step distance.
    var maxSev = {
      eq1: V40_MAX_SEVERITY.eq1[eq.eq1] * 0.1,
      eq2: V40_MAX_SEVERITY.eq2[eq.eq2] * 0.1,
      eq3eq6: (V40_MAX_SEVERITY.eq3eq6[eq.eq3] || {})[eq.eq6] * 0.1,
      eq4: V40_MAX_SEVERITY.eq4[eq.eq4] * 0.1,
      eq5: V40_MAX_SEVERITY.eq5[eq.eq5] * 0.1,
    };

    var meanDistance = 0;
    var nAxes = 0;
    ["eq1", "eq2", "eq3eq6", "eq4", "eq5"].forEach(function (axis) {
      var avail = stepAvail[axis];
      var d = sevDist[axis];
      var max = maxSev[axis];
      if (avail == null || !max) return;
      meanDistance += avail * (d / max);
      nAxes += 1;
    });
    var final = value - (nAxes > 0 ? meanDistance / nAxes : 0);
    if (final < 0) final = 0;
    if (final > 10) final = 10;
    var rounded = round1(final);
    return { score: rounded, label: severityLabel(rounded) };
  }

  // ---------------------------------------------------------------------------
  // Score dispatch
  // ---------------------------------------------------------------------------

  function computeScore(versionId, metrics) {
    if (versionId === "v2") return scoreV2(metrics);
    if (versionId === "v3.1") return scoreV31(metrics);
    return scoreV40(metrics);
  }

  // ---------------------------------------------------------------------------
  // Per-row controller
  // ---------------------------------------------------------------------------

  function typeSelect(row) { return row.querySelector("[data-severity-type]"); }
  function cvssInput(row) { return row.querySelector('[data-severity-score="cvss"]'); }
  function scoreBadge(row) { return row.querySelector("[data-cvss-score]"); }
  function calculator(row) { return row.querySelector("[data-cvss-calculator]"); }

  function activeVersionId(row) {
    var sel = typeSelect(row);
    if (!sel) return null;
    var v = VERSIONS[sel.value];
    return v ? v.id : null;
  }

  function ensureState(row) {
    if (row._cvssState) return row._cvssState;
    var sel = typeSelect(row);
    var input = cvssInput(row);
    var state = { "v2": { metrics: {} }, "v3.1": { metrics: {} }, "v4.0": { metrics: {} } };
    // Hydrate the bucket matching the row's current type from the persisted
    // free-text vector. The other buckets stay empty until the user touches
    // them.
    var v = sel && VERSIONS[sel.value];
    if (v && input && input.value) {
      state[v.id].metrics = parseVector(v.id, input.value);
    }
    row._cvssState = state;
    return state;
  }

  function setBadge(row, result) {
    var out = scoreBadge(row);
    if (!out) return;
    out.classList.remove("cvss-severity-low", "cvss-severity-medium", "cvss-severity-high", "cvss-severity-critical", "cvss-severity-none");
    if (!result) {
      out.textContent = "—";
      out.removeAttribute("data-score");
      return;
    }
    out.textContent = result.score.toFixed(1) + " (" + result.label + ")";
    out.setAttribute("data-score", String(result.score));
    out.classList.add(severityClass(result.label));
  }

  function renderCalculator(row) {
    var box = calculator(row);
    if (!box) return;
    var versionId = activeVersionId(row);
    if (!versionId) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    var state = ensureState(row);
    var metrics = state[versionId].metrics;
    var cat = metricCatalogue(versionId);

    var summary = box.querySelector("summary");
    var summaryText = "CVSS " + versionId + " calculator";
    if (!summary) {
      summary = document.createElement("summary");
      box.appendChild(summary);
    }
    summary.textContent = summaryText;

    // Clear and rebuild the inner content (everything after <summary>).
    while (summary.nextSibling) box.removeChild(summary.nextSibling);

    var groups = {};
    cat.forEach(function (m) { (groups[m.group] = groups[m.group] || []).push(m); });

    Object.keys(groups).forEach(function (groupName) {
      var fs = document.createElement("fieldset");
      fs.className = "cvss-group cvss-group-" + groupName.toLowerCase();
      var lg = document.createElement("legend");
      lg.textContent = groupName + " metrics";
      fs.appendChild(lg);
      groups[groupName].forEach(function (metric) {
        var wrap = document.createElement("div");
        wrap.className = "metric";
        var heading = document.createElement("label");
        heading.className = "metric-name";
        heading.textContent = metric.label + " (" + metric.id + ")";
        heading.title = metric.description;
        wrap.appendChild(heading);
        var select = document.createElement("select");
        select.dataset.cvssMetric = metric.id;
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = "—";
        select.appendChild(blank);
        metric.values.forEach(function (v) {
          var opt = document.createElement("option");
          opt.value = v.id;
          opt.textContent = v.label;
          opt.title = v.description;
          select.appendChild(opt);
        });
        select.value = metrics[metric.id] || "";
        wrap.appendChild(select);
        var help = document.createElement("small");
        help.className = "metric-help";
        var currentValue = metric.values.find(function (v) { return v.id === metrics[metric.id]; });
        help.textContent = currentValue ? currentValue.description : metric.description;
        wrap.appendChild(help);
        fs.appendChild(wrap);
      });
      box.appendChild(fs);
    });
  }

  function refreshScore(row) {
    var versionId = activeVersionId(row);
    if (!versionId) {
      setBadge(row, null);
      return;
    }
    var state = ensureState(row);
    var result = computeScore(versionId, state[versionId].metrics);
    setBadge(row, result);
  }

  function refresh(row) {
    var versionId = activeVersionId(row);
    var badge = scoreBadge(row);
    var box = calculator(row);
    if (!versionId) {
      if (badge) badge.hidden = true;
      if (box) box.hidden = true;
      return;
    }
    if (badge) badge.hidden = false;
    if (box) box.hidden = false;
    ensureState(row);
    renderCalculator(row);
    refreshScore(row);
  }

  function onMetricChange(row, metricId, value) {
    var versionId = activeVersionId(row);
    if (!versionId) return;
    var state = ensureState(row);
    if (value) state[versionId].metrics[metricId] = value;
    else delete state[versionId].metrics[metricId];
    var input = cvssInput(row);
    if (input) {
      input.value = buildVector(versionId, state[versionId].metrics);
    }
    refreshScore(row);
    // Update the help <small> next to the changed select.
    var sel = row.querySelector('[data-cvss-metric="' + metricId + '"]');
    if (sel) {
      var wrap = sel.closest(".metric");
      var help = wrap && wrap.querySelector(".metric-help");
      if (help) {
        var cat = metricCatalogue(versionId);
        var metric = cat.find(function (m) { return m.id === metricId; });
        var v = metric && metric.values.find(function (x) { return x.id === value; });
        help.textContent = v ? v.description : (metric ? metric.description : "");
      }
    }
  }

  function onFreeTextInput(row) {
    var versionId = activeVersionId(row);
    if (!versionId) return;
    var input = cvssInput(row);
    var state = ensureState(row);
    // If the new text belongs to a different CVSS version than the one the
    // dropdown is currently on (a typical paste-from-NVD scenario), swap the
    // dropdown so the calculator follows the pasted vector. Detection is
    // conservative — it only fires when the text either carries an explicit
    // CVSS:X.Y/ prefix or parses as a complete base under a single version.
    // Partial input keeps the existing behaviour so the user can still type
    // a half-finished vector under the active version.
    var detected = detectVersion(input.value, versionId);
    if (detected && detected !== versionId) {
      var sel = typeSelect(row);
      var newType = ID_TO_TYPE[detected];
      if (sel && newType) {
        sel.value = newType;
        // The detected version's bucket gets the freshly-parsed metrics;
        // the previously-active bucket is left alone so cycling back to it
        // restores whatever was there before the paste.
        state[detected].metrics = parseVector(detected, input.value);
        refresh(row);
        return;
      }
    }
    state[versionId].metrics = parseVector(versionId, input.value);
    renderCalculator(row);
    refreshScore(row);
  }

  function onTypeChange(row) {
    var sel = typeSelect(row);
    if (!sel) return;
    if (!VERSIONS[sel.value]) {
      // Switched to Ubuntu or similar. Hide calc + badge but keep state.
      refresh(row);
      return;
    }
    var newVersionId = VERSIONS[sel.value].id;
    var state = ensureState(row);
    var input = cvssInput(row);
    if (input) {
      // If the current input parses as a *complete base* under the new
      // version (e.g. the user pasted a v4 vector while the type was still
      // CVSS_V3, then realised and switched), accept it as the new-version
      // state instead of clobbering it. A partial parse — e.g. v3 vector
      // misread as v2 (AV/AC happen to overlap) — is rejected so we never
      // strand a half-translated vector in the bucket.
      var parsedAsNew = parseVector(newVersionId, input.value);
      if (hasFullBase(newVersionId, parsedAsNew)) {
        state[newVersionId].metrics = parsedAsNew;
        input.value = buildVector(newVersionId, parsedAsNew);
      } else {
        input.value = buildVector(newVersionId, state[newVersionId].metrics);
      }
    }
    refresh(row);
  }

  // ---------------------------------------------------------------------------
  // Event wiring
  // ---------------------------------------------------------------------------

  document.addEventListener("change", function (e) {
    var target = e.target;
    if (!(target instanceof Element)) return;
    if (target.matches("[data-cvss-metric]")) {
      var row = target.closest("[data-severity-row]");
      if (row) onMetricChange(row, target.dataset.cvssMetric, target.value);
    }
    if (target.matches("[data-severity-type]")) {
      var typeRow = target.closest("[data-severity-row]");
      if (typeRow) onTypeChange(typeRow);
    }
  });

  document.addEventListener("input", function (e) {
    var target = e.target;
    if (!(target instanceof Element)) return;
    if (target.matches('[data-severity-score="cvss"]')) {
      var row = target.closest("[data-severity-row]");
      if (row) onFreeTextInput(row);
    }
  });

  function refreshAll() {
    document.querySelectorAll("[data-severity-row]").forEach(refresh);
  }

  // Public hook used by advisoryhub-formsets.js after add/remove and on
  // type-toggle. Refreshing all rows is cheap enough (a handful at most).
  window.AdvisoryHubCvss = {
    refresh: function (row) { row ? refresh(row) : refreshAll(); },
    refreshAll: refreshAll,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", refreshAll);
  } else {
    refreshAll();
  }
})();
