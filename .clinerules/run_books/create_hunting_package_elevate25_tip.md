# Runbook: Creating of Hunting Packages leveraging Detection-as-Code Workflow for Elevate

## Objective

To leverage AI to extract the TTPs from a Campaign report from GTI, and leveraging Detection-as-Code methodology, deploy new detection rules on Github. 
If there are any YARA rules on the report, to create Livehunt Rules on Google Threat Intelligence

## Scope

This runbook leverages AI to extract information about a report, and analyse the TTPs within the report. It will then create rule in a specific format (YARA-L) for review, and upon approval, to commit it to a repository. Should there be any IOCs, it will create an IOC collection on Google Threat Intelligence / VirusTotal

## Inputs

*   `${CAMPAIGN_REPORT}`: Link to the report on Google Threat Intelligence
*   `${REPO_LOCATION}`: Location of the Rules to be deployed to
*   `${THREAT_INTEL_PLATFORM}`: The Threat Intel Platform for other sightings / additional enrichment
*   `${YARAL_STYLE_GUIDE}`: Link to the YARA-L Style Guide, found under elevate/.clinerules

## Tools

*   `gti-mcp`: `get_collection_report` `get_entities_related_to_a_collection`, `get_collection_timeline_events`, `search_threats`, `get_threat_intel` (to get information on report)
*   `opencti-mcp`: `get_latest_reports`, `search_indicators`, `search_malware`, `search_threat_actors`, `list_attack_patterns`, `get_campaigns_by_name`
*   `github-mcp`: `create_or_update_file` (for version control)
`create_detection_rule`
*   `secops-mcp`: `search_security_events` (for testing), `validate_udm_query` (if available), `list_security_rules` (to check existing rules)
*   `gti-hunting-mcp-server`: `create_hunting_ruleset`, `create_collection`

## Workflow Steps & Diagram

1.  **Campaign Input:** Provide the `${CAMPAIGN_REPORT}` to extract the TTPs from a Campaign report from GTI using `get_collection_report` `get_entities_related_to_a_collection`, `get_collection_timeline_events`, `search_threats`, `get_threat_intel`, `get_hunting_ruleset`
2.  **Additional Sightings:** Checks against `${THREAT_INTEL_PLATFORM}` for additional enrichment or other sightings using `get_latest_reports`, `search_indicators`, `search_malware`, `search_threat_actors`, `list_attack_patterns`, `get_campaigns_by_name`
3.  **Deployment of YARA-L Rules**: Creates a new rule in `${REPO_LOCATION}` using `create_or_update_file`, leveraging the github-mcp tool. 
4.  **Deployment of YARA Rules**: Creates a Livehunt Rule in Google Threat Intelligence using `create_hunting_ruleset`

```{mermaid}
sequenceDiagram
    participant security_engineer, threat_hunter
    participant Cline as Cline (MCP Client)
    participant SIEM as secops-mcp
    participant git as Git 
    participant SOAR as secops-soar (Optional)
    participant GTI as gti-mcp
    participant TIP as opencti-mcp
    participant VT as gti-hunting-mcp-server

    security_engineer/threat_hunter->>Cline: Start Detection-as-Code Workflow\nInput: RULE_IDEA, LOG_SOURCES, TEST_DATA...

    %% Step 1: Analyse Campaign Report
    Cline->>GTI: get_collection_report, get_entities_related_to_a_collection, get_collection_timeline_events, search_threats, get_threat_intel
    Extract the report details, such as TTPs, behavioural indicators, and IOCs from the report.

    %% Step 2: Search TIP
    Cline->>TIP: get_latest_reports, search_indicators, search_malware, search_threat_actors
    Enrich the information from Step 1 from the TIP with any new TTPs, indicators or malwares.  

    %% Step 3: Analyse the TTPs and behaviours retrieved from Step 1 and Step 2
    Cline->>Analyst: Present the TTPs and behaviours to the analyst for review and ask for confirmation to proceed.

    %% Step 4: Rule Development
    Using the information from Step 3, draft a YARA-L rule based on the ttps and behaviours and present it to the user. Use the YARA-L style guide titled "SECOPS_YARAL_STYLE_GUIDE.md", "YARAL_SYNTAX.md", "OVERVIEW_OF_YARAL_LANGUAGE" from elevate2025/.clinerules. Append the "-elevate2025" to the fiulename. 

    %% Step 5: Ask User
    Cline->>Analyst: Ask the user to review the YARA-L rules created. 
    
    %% Step 6: Commit the YARA-L Rules to Repository
    Cline->>Github: create_or_update_file in ${REPO_LOCATION} and commit them to the repository 

    %% Step 7: Show all IOCs to the user
    Cline->>Analyst: Summarise the report to the analyst, listing all threat actors, malwares, vulnerabilities to the analyst. Show all IOCs in a table format

    (OPTIONAL) 
    %% Step 8: If there are any YARA rules in the report, create a YARA rule in gti-hunting-mcp-server. Make sure it if from the YARA rule, specifically from the `get_hunting_ruleset`
    Cline->>GTI: get_collection_report, get_entities_related_to_a_collection, get_collection_timeline_events, search_threats, get_threat_intel, get_hunting_ruleset
    Note, use the hunting_rulesets relationship in the `get_collection_report` tool 	
    Cline->>TIP: search_indicators, search_malware, search_threat_actors

    %% Step 9: If there are any indicators in the report, run create_collection.

    Cline->>Developer/Engineer: attempt_completion(result="Hunting Package created.")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Rule successfully deployed to production environment, monitoring initiated.)*
