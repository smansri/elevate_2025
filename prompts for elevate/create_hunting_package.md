# Runbook: Creating of Hunting Packages leveraging Detection-as-Code Workflow for Elevate

## Objective

To leverage AI to extract the TTPs from a Campaign report from GTI, and leveraging Detection-as-Code methodology, to develope, test, review and deploy new detection rules to for both Livehunt rules in SecOps and Google Threat Intelligence

## Scope

This runbook covers the insight from 
*(Define what is included/excluded, e.g., Covers rule creation in a specific format (YARA-L, Sigma), testing procedures, peer review process, and deployment mechanism. Excludes infrastructure setup for the pipeline.)*

## Inputs

*   `${RULE_IDEA}`: Description of the threat or behavior the new rule should detect.
*   `${RELEVANT_LOG_SOURCES}`: Log sources needed for the detection.
*   `${TEST_DATA_LOCATION}`: Location of data suitable for testing the rule.
*   *(Optional) `${VERSION_CONTROL_BRANCH}`: Branch for developing the rule.*

## Tools

*   `gti-mcp`: `get_collection_report` `get_entities_related_to_a_collection`, `get_collection_timeline_events`, `search_threats`, `get_threat_intel` (to get information on report)
*   `opencti-mcp`: `get_latest_reports`, `search_indicators`, `search_malware`, `search_threat_actors`, `list_attack_patterns`, `get_campaigns_by_name`
*   `github-mcp`: `create_or_update_file` (for version control)
`create_detection_rule`
*   `secops-mcp`: `search_security_events` (for testing), `validate_udm_query` (if available), `list_security_rules` (to check existing rules)
*   `virustotal-mcp`: `create_hunting_ruleset`, `create_collection`


## Workflow Steps & Diagram

1.  **Campaign Input:** Provide the `${CAMPAIGN_REPORT_NAME}` to extract the TTPs from a Campaign report from GTI.
2.  **Testing:**   Test rule logic against `${TEST_DATA_LOCATION}` using `search_security_events` or other methods. Validate syntax (e.g., `validate_udm_query`).
3.  **Version Control:** Commit the rule definition to the appropriate `${VERSION_CONTROL_BRANCH}`.
4.  **Peer Review:** Initiate a code review process for the new rule.
5.  **Deployment:** Merge the rule to the main branch and trigger the deployment pipeline (or manually deploy using appropriate tools like `create_detection_rule`).
6.  **Create Hunting Package on Livehunt using virustotal-mcp where appropriate
7.  **Monitoring:** Monitor the rule's performance post-deployment.

```{mermaid}
sequenceDiagram
    participant security_engineer, threat_hunter
    participant Cline as Cline (MCP Client)
    participant SIEM as secops-mcp
    participant VersionControl as Git 
    participant CI_CD as CI/CD Pipeline (Conceptual)
    participant SOAR as secops-soar (Optional)
    participant CTI as gti-mcp
    participant TIP as opencti-mcp

    security_engineer/threat_hunter->>Cline: Start Detection-as-Code Workflow\nInput: RULE_IDEA, LOG_SOURCES, TEST_DATA...

    %% Step 1: Rule Development
    Note over Cline: Draft detection logic (e.g., YARA-L)

    %% Step 2: Testing
    Cline->>SIEM: search_security_events(text="Test Query for Rule", ...)
    SIEM-->>Cline: Test Results
    opt Validate Query Tool Available
        Cline->>SIEM: validate_udm_query(query=...)
        SIEM-->>Cline: Validation Result
    end
    Note over Cline: Refine rule based on testing

    %% Step 3: Version Control
    Cline->>VersionControl: (Conceptual) Commit rule definition to branch

    %% Step 4: Peer Review
    Note over Cline: Initiate Peer Review Process (Manual/External)

    %% Step 5: Deployment
    Cline->>VersionControl: (Conceptual) Merge rule to main branch
    VersionControl->>CI_CD: (Conceptual) Trigger Deployment Pipeline
    CI_CD->>SIEM: (Conceptual) Deploy rule (e.g., via create_detection_rule)
    SIEM-->>CI_CD: Deployment Status
    CI_CD-->>Cline: Deployment Result

    %% Step 6: Monitoring
    Note over Cline: Monitor rule performance (Manual/Alerting)
    opt Document Deployment
        Cline->>SOAR: post_case_comment(case_id=..., comment="Rule [Rule Name] deployed via DaC workflow.")
        SOAR-->>Cline: Comment Confirmation
    end

    Cline->>Developer/Engineer: attempt_completion(result="Detection-as-Code workflow initiated/completed for rule idea. Deployment status: [...]")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Rule successfully deployed to production environment, monitoring initiated.)*
