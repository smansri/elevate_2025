# Runbook: Creating of Hunting Packages leveraging Detection-as-Code Workflow for Elevate

## Objective

To leverage AI to extract the TTPs from a Campaign report from GTI, and leveraging Detection-as-Code methodology, deploy new detection rules on Google SecOps, and if there are any YARA rules on the report, to create Livehunt Rules on Google Threat Intelligence

## Scope

This runbook covers the insight from 
*(Define what is included/excluded, e.g., Covers rule creation in a specific format (YARA-L, Sigma), testing procedures, peer review process, and deployment mechanism. Excludes infrastructure setup for the pipeline.)*

## Inputs

*   `${CAMPAIGN_REPORT}`: Link to the report on Google Threat Intelligence
*   `${RULE_LOCATION}`: Location of the Rules to be deployed to
*   `${THREAT_INTEL_PLATFORM}`: The Threat Intel Platform for other sightings / additional enrichment

## Tools

*   `gti-mcp`: `get_collection_report` `get_entities_related_to_a_collection`, `get_collection_timeline_events`, `search_threats`, `get_threat_intel` (to get information on report)
*   `opencti-mcp`: `get_latest_reports`, `search_indicators`, `search_malware`, `search_threat_actors`, `list_attack_patterns`, `get_campaigns_by_name`
*   `github-mcp`: `create_or_update_file` (for version control)
`create_detection_rule`
*   `secops-mcp`: `search_security_events` (for testing), `validate_udm_query` (if available), `list_security_rules` (to check existing rules)
*   `virustotal-mcp`: `create_hunting_ruleset`, `create_collection`


## Workflow Steps & Diagram

1.  **Campaign Input:** Provide the `${CAMPAIGN_REPORT}` to extract the TTPs from a Campaign report from GTI using `get_collection_report` `get_entities_related_to_a_collection`, `get_collection_timeline_events`, `search_threats`, `get_threat_intel`
2.  **Additional Sightings:** Checks against `${THREAT_INTEL_PLATFORM}` for additional enrichment or other sightings using `get_latest_reports`, `search_indicators`, `search_malware`, `search_threat_actors`, `list_attack_patterns`, `get_campaigns_by_name`
3.  **Deployment of YARA-L Rules**: Creates a new rule in `${RULE_LOCATION}` using `create_or_update_file`
4.  **Deployment of YARA Rules**: Creates a Livehunt Rule in Google Threat Intelligence using `create_hunting_ruleset`

```{mermaid}
sequenceDiagram
    participant security_engineer, threat_hunter
    participant Cline as Cline (MCP Client)
    participant SIEM as secops-mcp
    participant VersionControl as Git 
    participant CI_CD as CI/CD Pipeline (Conceptual)
    participant SOAR as secops-soar (Optional)
    participant GTI as gti-mcp
    participant TIP as opencti-mcp
    participant VT as virustotal-mcp

    security_engineer/threat_hunter->>Cline: Start Detection-as-Code Workflow\nInput: RULE_IDEA, LOG_SOURCES, TEST_DATA...

    %% Step 1: Analyse Campaign Report
    Cline->>GTI: get_collection_report, get_entities_related_to_a_collection, get_collection_timeline_events, search_threats, get_threat_intel
    Extract threat actors, malwares, ttps. Extract any YARA rules from the report

    %% Step 2: Search TIP
    Cline->>TIP: get_latest_reports, search_indicators, search_malware, search_threat_actors
    Enrich information from Step 1 from TIP. 

    %% Step 3: Rule Development
    Note: Draft YARA-L Rule based on the TTPs found in the report and present to user

    %% Step 4: Ask User
    Cline->>User: Ask the user to review the YARA-L rules created. 
    
    %% Step 5: Commit the YARA-L Rules to Repository
    Cline->>Github: create_or_update_file in google_secops/rules repository

    (OPTIONAL) 
    %% Step 6: Extract YARA rules from Campaign Report or TIP if any
    Cline->>GTI: get_collection_report, get_entities_related_to_a_collection, get_collection_timeline_events, search_threats, get_threat_intel
    Cline->>TIP: search_indicators, search_malware, search_threat_actors
    
    %% Step 7: Create Livehunt Rules in Google Threat Intelligence
    Cline->>VT `create_hunting_ruleset`

    Cline->>Developer/Engineer: attempt_completion(result="Hunting Package created.")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Rule successfully deployed to production environment, monitoring initiated.)*
