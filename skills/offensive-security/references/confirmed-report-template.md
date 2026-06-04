# Offensive Security — Confirmed Vulnerabilities Report

**Generated:** {{ timestamp }}  
**Target:** {{ target }}  
**Hypotheses:** {{ total_hypotheses }} | **Confirmed:** {{ confirmed_count }} | **Rate:** {{ confirmation_rate }}%

## Risk Rating

**Overall:** {{ risk_rating }}

{% if executive_summary %}
## Executive Summary

{{ executive_summary }}
{% endif %}

## Confirmed Vulnerabilities

{% for item in confirmed %}
### {{ loop.index }}. [{{ item.severity }}] {{ item.title }}

| Field | Value |
|-------|-------|
| Finding ID | `{{ item.finding_id }}` |
| Hypothesis ID | `{{ item.hypothesis_id }}` |
| Category | {{ item.category }} |
| Source skill | {{ item.source_skill }} |
| Blast radius | {{ item.blast_radius }} |
| Remediation priority | {{ item.remediation_priority }} |

**Hypothesis:** {{ item.hypothesis_title }}

**Proof of concept:**

{% for step in item.poc_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

**Evidence:**

```
{{ item.evidence }}
```

**Negative control:**

{{ item.negative_control }}

---
{% else %}
_No confirmed vulnerabilities in this run._
{% endfor %}

## Inconclusive / Needs Info

{% for item in inconclusive %}
- **{{ item.title }}** ({{ item.hypothesis_id }}): {{ item.rationale }}  
  _Retry:_ {{ item.retry_suggestion }}
{% else %}
_None._
{% endfor %}

## False Positives

{% for item in false_positives %}
- **{{ item.rule_id }}** @ `{{ item.file }}`:{{ item.line }} — {{ item.rationale }}
{% else %}
_None._
{% endfor %}

## Chaining Map

{% if chaining_mermaid %}
```mermaid
{{ chaining_mermaid }}
```
{% endif %}

{{ chaining_text }}

## Remediation Roadmap

| Priority | Finding | Severity | Blast | Effort |
|----------|---------|----------|-------|--------|
{% for row in remediation_roadmap %}
| {{ row.priority }} | {{ row.title }} | {{ row.severity }} | {{ row.blast_radius }} | {{ row.effort }} |
{% endfor %}

## Appendix

### Hypothesis inventory

{% for h in all_hypotheses %}
- `{{ h.hypothesis_id }}` — {{ h.title }} → **{{ h.outcome }}**
{% endfor %}

### Validation environment

- Scope file: {{ scope_file }}
- Docker available: {{ docker_available }}
- Dry run: {{ dry_run }}

### Runtime stats

- Duration: {{ runtime_seconds }}s
- Sandboxes torn down: {{ sandboxes_torn_down }}
