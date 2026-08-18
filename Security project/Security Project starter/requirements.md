# Requirements Document

## Introduction

The Prompt Injection Detector is a locally-hosted desktop tool designed as a demo for an executive team. It analyzes user prompts sent to a Large Language Model (LLM) and flags potential injection attacks, including jailbreaks and indirect prompt injections. The tool provides a visually compelling dashboard displaying classification results (safe vs. malicious) along with confidence scores, making it easy for non-technical stakeholders to understand prompt injection threats at a glance.

## Glossary

- **Detector**: The core analysis engine that classifies prompts as safe or malicious
- **Dashboard**: The primary visual interface displaying prompt analysis results and metrics
- **Prompt**: A text input intended to be sent to an LLM
- **Prompt_Injection**: A technique where malicious instructions are embedded in a prompt to manipulate LLM behavior
- **Jailbreak**: A category of prompt injection that attempts to override the LLM's safety guardrails or system instructions
- **Indirect_Injection**: A category of prompt injection where malicious instructions are hidden within data the LLM processes (e.g., embedded in documents, URLs, or other content)
- **Confidence_Score**: A numerical value between 0.0 and 1.0 representing the Detector's certainty in its classification
- **Classification**: The categorization of a prompt as either "safe" or "malicious"
- **Threat_Type**: The specific category of detected injection attack (jailbreak, indirect injection, or none)

## Requirements

### Requirement 1: Prompt Analysis

**User Story:** As a demo viewer, I want to submit prompts for analysis, so that I can see how the tool detects injection attacks.

#### Acceptance Criteria

1. WHEN a prompt is submitted, THE Detector SHALL classify the prompt as either "safe" or "malicious" within 3 seconds
2. WHEN a prompt is classified, THE Detector SHALL assign a Confidence_Score between 0.0 and 1.0 (inclusive, rounded to two decimal places) to the Classification
3. WHEN a malicious prompt is detected, THE Detector SHALL identify the Threat_Type as either "jailbreak" or "indirect_injection"
4. WHEN a safe prompt is analyzed, THE Detector SHALL assign a Threat_Type of "none"
5. THE Detector SHALL accept prompts containing between 1 and 10,000 characters, where a character is any visible or whitespace Unicode character
6. IF a submitted prompt is empty, contains only whitespace, or exceeds 10,000 characters, THEN THE Detector SHALL reject the submission and display an error message indicating the accepted character length range
7. IF the Detector fails to complete classification within 3 seconds, THEN THE Detector SHALL display an error message indicating that analysis timed out and allow the user to resubmit the prompt

### Requirement 2: Jailbreak Detection

**User Story:** As a demo viewer, I want the tool to identify jailbreak attempts, so that I can understand how attackers try to bypass LLM safety guardrails.

#### Acceptance Criteria

1. WHEN a prompt contains instructions to ignore, override, or disable system rules or safety guidelines, THE Detector SHALL classify the prompt as malicious with Threat_Type "jailbreak"
2. WHEN a prompt contains role-play scenarios that instruct the LLM to assume a persona without safety restrictions or to respond as if guardrails do not apply, THE Detector SHALL classify the prompt as malicious with Threat_Type "jailbreak"
3. WHEN a prompt contains requests to act as an unrestricted AI with no content limitations, THE Detector SHALL classify the prompt as malicious with Threat_Type "jailbreak"
4. WHEN a prompt contains role-play or creative writing requests that do not instruct the LLM to bypass safety restrictions or ignore system rules, THE Detector SHALL classify the prompt as safe
5. IF a prompt contains both jailbreak indicators and legitimate content, THEN THE Detector SHALL classify the prompt as malicious with Threat_Type "jailbreak" and assign a Confidence_Score of 0.5 or above
6. WHEN a prompt is classified as malicious with Threat_Type "jailbreak", THE Detector SHALL assign a Confidence_Score of 0.5 or above to the Classification

### Requirement 3: Indirect Prompt Injection Detection

**User Story:** As a demo viewer, I want the tool to identify indirect prompt injection attacks, so that I can understand how malicious instructions can be hidden in data.

#### Acceptance Criteria

1. WHEN a prompt contains instructions embedded within quoted text, document excerpts, or simulated external data sources that direct the LLM to perform actions contrary to its intended purpose, THE Detector SHALL classify the prompt as malicious with Threat_Type "indirect_injection"
2. WHEN a prompt contains instructions that are encoded using techniques such as base64, hexadecimal, unicode escaping, or character substitution to obscure their intent from human review, THE Detector SHALL classify the prompt as malicious with Threat_Type "indirect_injection"
3. WHEN a prompt contains injected instructions positioned as context, examples, or reference material that attempt to override or redirect the LLM's original task, THE Detector SHALL classify the prompt as malicious with Threat_Type "indirect_injection"
4. WHEN a prompt contains quoted text, encoded content, or contextual examples that do not attempt to override or redirect the LLM's intended behavior, THE Detector SHALL classify the prompt as safe

### Requirement 4: Dashboard Display

**User Story:** As a demo viewer, I want to see a visually compelling dashboard, so that I can quickly understand the distribution of safe vs. malicious prompts.

#### Acceptance Criteria

1. THE Dashboard SHALL display a summary showing the total count of analyzed prompts, the count of safe prompts, and the count of malicious prompts
2. THE Dashboard SHALL display a visual chart showing the ratio of safe to malicious prompts
3. THE Dashboard SHALL display each analyzed prompt with its Classification, Confidence_Score, and Threat_Type, truncating prompt text that exceeds 200 characters with a visible indicator that the text has been truncated
4. THE Dashboard SHALL use color coding to distinguish safe prompts (green) from malicious prompts (red)
5. THE Dashboard SHALL sort analyzed prompts by submission time with the most recent prompt displayed first
6. IF no prompts have been analyzed, THEN THE Dashboard SHALL display the summary counts as zero and show a placeholder message in the prompt list area indicating no prompts have been analyzed yet

### Requirement 5: Confidence Score Visualization

**User Story:** As a demo viewer, I want to see confidence scores displayed visually, so that I can understand how certain the tool is about each classification.

#### Acceptance Criteria

1. THE Dashboard SHALL display the Confidence_Score as a numerical value rounded to 2 decimal places and a visual progress indicator filled proportionally from 0% (score 0.0) to 100% (score 1.0) for each analyzed prompt
2. WHEN a Confidence_Score is greater than 0.8, THE Dashboard SHALL label the result as "High Confidence" and display the progress indicator in green
3. WHEN a Confidence_Score is between 0.5 and 0.8 inclusive, THE Dashboard SHALL label the result as "Medium Confidence" and display the progress indicator in yellow
4. WHEN a Confidence_Score is less than 0.5, THE Dashboard SHALL label the result as "Low Confidence" and display the progress indicator in red
5. THE Dashboard SHALL display the confidence label adjacent to the progress indicator for each analyzed prompt

### Requirement 6: Scenario-Based Demo Prompts

**User Story:** As a demo presenter, I want pre-built prompts organized by real-life cyber threat scenarios, so that I can walk executives through realistic attack demonstrations with a single click.

#### Acceptance Criteria

1. THE Dashboard SHALL display pre-built demo prompts organized into named scenario categories, with each category representing a real-world cyber threat use case
2. THE Dashboard SHALL include the following scenario categories at minimum: "Corporate Data Exfiltration", "Customer Service Bot Hijacking", "AI Assistant Jailbreak", "Document Poisoning Attack", and "Legitimate Business Use"
3. WHEN a scenario category is selected, THE Dashboard SHALL display all prompts within that scenario, each showing a short description label and the prompt text
4. WHEN a pre-built prompt is clicked, THE Dashboard SHALL automatically submit the prompt for analysis and display the result
5. THE Dashboard SHALL include at least 3 prompts per scenario category, providing a mix of attack stages or variations within each scenario
6. EACH scenario category SHALL display a brief description (1-2 sentences) explaining the real-world threat context before listing its prompts
7. THE Dashboard SHALL include pre-built prompts that cover all Threat_Types: at least 3 prompts classified as "jailbreak", at least 3 classified as "indirect_injection", and at least 3 classified as safe
8. THE Dashboard SHALL provide a "Run Full Demo" action that executes one prompt from each scenario category sequentially, pausing 2 seconds between submissions to allow the audience to observe each result
9. IF the "Run Full Demo" action is triggered while a previous execution is still in progress, THEN THE Dashboard SHALL disable the action until the current execution completes
10. EACH pre-built prompt SHALL display a tooltip or expandable section explaining why it is classified as safe or malicious, describing the specific attack technique used
11. THE Dashboard SHALL provide a "Run All Scenarios" action that submits all pre-built prompts across all categories sequentially, displaying a progress count indicating how many of the total prompts have been submitted

### Requirement 7: Real-Time Feedback

**User Story:** As a demo viewer, I want to see results appear immediately after submitting a prompt, so that the demo feels responsive and engaging.

#### Acceptance Criteria

1. WHILE the Detector is processing a prompt, THE Dashboard SHALL display a loading indicator, and WHEN processing completes or fails, THE Dashboard SHALL remove the loading indicator within 500 milliseconds
2. WHEN analysis is complete, THE Dashboard SHALL animate the result into the prompt list with a visible transition lasting no longer than 500 milliseconds
3. WHEN a new result is added, THE Dashboard SHALL update the summary counts and chart within 1 second without requiring a page refresh
4. IF the Detector fails to return a result within 3 seconds or encounters an error during analysis, THEN THE Dashboard SHALL remove the loading indicator and display an error message indicating that analysis could not be completed

### Requirement 8: Local Desktop Hosting

**User Story:** As a demo presenter, I want the tool to run entirely on a local desktop, so that I can present it without requiring network connectivity.

#### Acceptance Criteria

1. THE Detector SHALL operate without requiring external network requests during startup or analysis
2. THE Dashboard SHALL be accessible via a local web browser at a localhost URL on a configurable port with a default of 8080
3. WHEN the application is started, THE Dashboard SHALL respond to browser requests with the main dashboard page within 10 seconds
4. WHEN the application is started, THE system SHALL display a ready message in the terminal indicating the localhost URL where the Dashboard is accessible
5. IF the configured port is already in use, THEN THE system SHALL display an error message indicating the port conflict and exit without starting
6. THE system SHALL start via a single terminal command without requiring additional manual configuration steps
