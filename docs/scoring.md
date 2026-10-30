# Risk Scoring Methodology

The auditor computes a deterministic, multi-factor risk score between 0.0 and 100.0. AI and LLM components are strictly prohibited from generating or modifying numerical scores.

## 1. Finding Base Scores
Each finding receives a base score derived from its severity:
- `CRITICAL`: 10.0
- `HIGH`: 7.5
- `MEDIUM`: 5.0
- `LOW`: 2.5
- `INFO`: 0.5

## 2. Trigger Context Multipliers
Workflows triggered by external or untrusted entities have their risks multiplied:
- `pull_request_target`: 1.5x
- `workflow_run`: 1.3x
- `issues` / `issue_comment`: 1.2x
- `pull_request` / `push`: 1.0x
- `schedule`: 0.9x

## 3. Attack Chain Amplification
Correlated multi-stage attack chains amplify individual finding weights:
- `pwn-request`: 1.6x
- `injection-to-exfil`: 1.5x
- `supply-chain-takeover`: 1.4x
- `runner-persistence`: 1.4x
- `deploy-blast-radius`: 1.3x

## 4. Aggregate Score Normalization
The holistic repository score is calculated using asymptotic normalization:
$$Score = \min\left(100.0, \sum (\text{Base} \times \text{TriggerMultiplier}) \times \prod \text{ChainAmplification}\right)$$

Categorical Risk Bands:
- `0.0 - 24.9`: **LOW**
- `25.0 - 49.9`: **MEDIUM**
- `50.0 - 74.9`: **HIGH**
- `75.0 - 100.0`: **CRITICAL**

