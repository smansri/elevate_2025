# Overview of the YARA-L 2.0 language

Supported in:

Google secops
[Siem](/chronicle/docs/secops/google-secops-siem-toc)

YARA-L 2.0 is a computer language used to create rules for searching through your enterprise log data as it is ingested into your Google Security Operations instance. The YARA-L syntax is derived from the YARA language developed by VirusTotal.
The language works in conjunction with the Google SecOps Detection Engine and enables you to hunt for threats and other events across large volumes of data.

For more information, see the following:

* [YARA-L 2.0 language syntax](/chronicle/docs/detection/yara-l-2-0-syntax)
* [Best practices](/chronicle/docs/detection/yara-l-best-practices)

**Note:** YARA-L 2.0 is incompatible with previous versions of the YARA-L language. Rules written in older versions of YARA-L will not work with the current version of the Detection Engine and need to be revised to use the new syntax.

## YARA-L 2.0 example rules

The following examples show rules written in YARA-L 2.0. Each demonstrates how to correlate events within the rule language.

### Rules and tuning

The following rule checks for specific patterns in event data and creates a detection
if it finds the patterns. This rule includes a variable `$e1` for tracking event
type and `metadata.event_type` UDM field. The rule checks for specific occurrences
of regular expression matches with `e1`. When the event `$e1` takes place, a detection is created.
A `not` condition is included in the rule to exclude certain non-malicious paths.
You can add `not` conditions to prevent false positives.

```
rule suspicious_unusual_location_svchost_execution
{

 meta:
   author = "Google Cloud Security"
   description = "Windows 'svchost' executed from an unusual location"
   yara_version = "YL2.0"
   rule_version = "1.0"

 events:

   $e1.metadata.event_type = "PROCESS_LAUNCH"
   re.regex($e1.principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
   not re.regex($e1.principal.process.command_line, `\\Windows\\System32\\`) nocase

condition:

   $e1
}


```

### Logins from different cities

The following rule searches for users that have logged in to your enterprise from two or more cities in less than 5 minutes:

```
rule DifferentCityLogin {
  meta:

  events:
    $udm.metadata.event_type = "USER_LOGIN"
    $udm.principal.user.userid = $user
    $udm.principal.location.city = $city

  match:
    $user over 5m

  condition:
    $udm and #city > 1
}

```

**Match variable**: `$user`

**Event variable**:`$udm`

**Placeholder variable**: `$city` and `$user`

The following describes how this rule works:

* Groups events with username (`$user`) and returns it (`$user`) when a match is found.
* Timespan is 5 minutes, meaning only events that are less than 5 minutes apart are correlated.
* Searching for an event group (`$udm`) whose event type is *USER\_LOGIN*.
* For that event group, the rule calls the user ID as `$user` and the login city as `$city.`
* Returns a match if the distinct number of `city` values (denoted by `#city`) is greater than 1 in the event group (`$udm`) within the 5 minute time range.

### Rapid user creation and deletion

The following rule searches for users that have been created and then deleted within 4 hours:

```
rule UserCreationThenDeletion {
  meta:

  events:
    $create.target.user.userid = $user
    $create.metadata.event_type = "USER_CREATION"

    $delete.target.user.userid = $user
    $delete.metadata.event_type = "USER_DELETION"

    $create.metadata.event_timestamp.seconds <=
       $delete.metadata.event_timestamp.seconds

  match:
    $user over 4h

  condition:
    $create and $delete
}

```

**Event variables**:`$create` and `$delete`

**Match variable**: `$user`

**Placeholder variable**: N/A

The following describes how this rule works:

* Groups events with username (`$user`) and returns it (`$user`) when a match is found.
* Time window is 4 hours, meaning only events separated by less than 4 hours are correlated.
* Searches for two event groups (`$create` and `$delete`, where `$create` is equivalent to `#create >= 1`).
* `$create` corresponds to `USER_CREATION` events and calls the user ID as `$user`.
* `$user` is used to join the two groups of events together.
* `$delete` corresponds to `USER_DELETION` events and calls the user ID as `$user`. This rule looks for a match where the user identifier in the two event groups is the same.
* This rule looks for cases where the event from `$delete` happens later than the event from `$create`, returning a match when discovered.

### Single event rule

Single event rules are rules that correlate over a single event. A single event rule can be:

* Any rule without a match section.
* Rule with a `match` section and a `condition` section only checking for the existence of 1 event (for example, "$e", "#e > 0", "#e >= 1", "1 <= #e", "0 < #e").

For example, the following rule searches for a user login event and would return the first one it encounters within the enterprise data stored within your Google SecOps account:

```
rule SingleEventRule {
  meta:
    author = "noone@altostrat.com"

  events:
    $e.metadata.event_type = "USER_LOGIN"

  condition:
    $e
}

```

Here is another example of a single event rule with a match section. This rule searches for a user who has logged in at least once in less than 5 minutes. It checks for the simple existence of a user login event.

```
rule SingleEventRule {
  meta:
    author = "alice@example.com"
    description = "windowed single event example rule"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.user.userid = $user

  match:
    $user over 5m

  condition:
    #e > 0
}

```

**Note:** Rules with a `match` section and a `condition` section that includes outcome variables in addition to simple existence on 1 event are classified as [multi-event rules](#multiple_event_rule). In these rules, detection generation logic depends on all events in a match window (for example, many events), rather than any event in a match window (for example, single event). The following example of such rules generates the same detections as the first multi-event rule example in the next section.

```
rule MultiEventRule{
  meta:
    author = "alice@example.com"
    description = "Rule with outcome condition and simple existence condition on one event variable"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.user.userid = $user

  match:
    $user over 10m

  outcome:
    $num_events_in_match_window = count($e.metadata.id)

  condition:
    #e > 0 and $num_events_in_match_window >= 10 // Could be rewritten as #e >= 10
}

```

### Multiple event rule

Use multiple event rules to group many events over a specified time window and try to find correlations between events. A typical multiple event rule will have the following:

* A `match` section which specifies the time range over which events need to be grouped.
* A `condition` section specifying what condition should trigger the detection and checking for the existence of multiple events.

For example, the following rule searches for a user who has logged in at least 10 times in less than 10 minutes:

```
rule MultiEventRule {
  meta:
    author = "noone@altostrat.com"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.user.userid = $user

  match:
    $user over 10m

  condition:
    #e >= 10
}

```

### Single event within range of IP addresses

The following example shows a single event rule searching for a match between two specific users and a specific range of IP addresses:

```
rule OrsAndNetworkRange {
  meta:
    author = "noone@altostrat.com"

  events:
    // Checks CIDR ranges.
    net.ip_in_range_cidr($e.principal.ip, "203.0.113.0/24")

    // Detection when the hostname field matches either value using or.
    $e.principal.hostname = /pbateman/ or $e.principal.hostname = /sspade/

  condition:
    $e
}

```

### any and all rule example

The following rule searches for login events where all source IP addresses do not match an IP address known to be secure within a timespan of 5 minutes.

```
rule SuspiciousIPLogins {
  meta:
    author = "alice@example.com"

  events:
    $e.metadata.event_type = "USER_LOGIN"

    // Detects if all source IP addresses in an event do not match "100.97.16.0"
    // For example, if an event has source IP addresses
    // ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
    // it will be detected since "100.97.16.1", "100.97.16.2",
    // and "100.97.16.3" all do not match "100.97.16.0".

    all $e.principal.ip != "100.97.16.0"

    // Assigns placeholder variable $ip to the $e.principal.ip repeated field.
    // There will be one detection per source IP address.
    // For example, if an event has source IP addresses
    // ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
    // there will be one detection per address.

    $e.principal.ip = $ip

  match:
    $ip over 5m

  condition:
    $e
}

```

### Regular expressions in a rule

The following YARA-L 2.0 regular expression example searches for events with emails received from the altostrat.com domain. Since `nocase` has been added to the `$host` variable `regex` comparison and the `regex` function, both these comparisons are case insensitive.

```
rule RegexRuleExample {
  meta:
    author = "noone@altostrat.com"

  events:
    $e.principal.hostname = $host
    $host = /.*HoSt.*/ nocase
    re.regex($e.network.email.from, `.*altostrat\.com`) nocase

  match:
    $host over 10m

  condition:
    #e > 10
}

```

### Composite rule examples

**Note:** This feature is covered by [Pre-GA Offerings Terms](https://chronicle.security/legal/service-terms/) of the Google Security Operations Service
Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions.
For more information, see the [Google SecOps Technical Support Service guidelines](https://chronicle.security/legal/technical-support-services-guidelines/)
and the [Google SecOps Service Specific Terms](https://chronicle.security/legal/service-terms/).

Composite detections enhance threat detection by using composite rules.
These composite rules use detections from other rules as their input. This enables
the detection of complex threats that individual rules might not detect. For
more information, see [Overview of composite detections](/chronicle/docs/detection/composite-detections).

#### Tripwire detections

Tripwire composite detections are the simplest form of a composite detection
that operates on fields within detection findings, such as outcome variables or
rule metadata. They help filter detections for conditions that may indicate
higher risk, such as an administrator user or a production environment.

```
rule composite_admin_detection {
  meta:
    rule_name = "Detection with Admin User"
    author = "Google Cloud Security"
    description = "Composite rule that looks for any detections where the actor is an admin user"
    severity = "Medium"

  events:
    $rule_name = $d.detection.detection.rule_name
    $principal_user = $d.detection.detection.outcomes["principal_users"]
    $principal_user = /admin|root/ nocase

  match:
    $principal_user over 1h

  outcome:
    $risk_score = 75
    $upstream_rules = array_distinct($rule_name)

  condition:
    $d
}

```

#### Threshold and Aggregation detections

Aggregation composite detection rules let you group detection findings based
on shared attributes, such as a hostname or username, and analyze the aggregated
data. The following are common use cases:

* Identifying users who generate a high volume of security alerts or aggregated risk.
* Detecting hosts with unusual activity patterns by aggregating related detections.

Risk aggregation example:

```
rule composite_risk_aggregation {
  meta:
    rule_name = "Risk Aggregation Composite"
    author = "Google Cloud Security"
    description = "Composite detection that aggregates risk of a user over 48 hours"
    severity = "High"

  events:
    $rule_name = $d.detection.detection.rule_name
    $principal_user = $d.detection.detection.outcomes["principal_users"]
    $risk = $d.detection.detection.risk_score

  match:
    $principal_user over 48h

  outcome:
    $risk_score = 90
    $cumulative_risk = sum($risk)
    $principal_users = array_distinct($principal_users)
    $upstream_rules = array_distinct($rule_name)

  condition:
    $d and $cumulative_risk > 500
}

```

Tactic aggregation example:

```
rule composite_tactic_aggregation {
  meta:
    rule_name = "MITRE Tactic Aggregation Composite"
    author = "Google Cloud Security"
    description = "Composite detection that detects if a user has triggered detections over multiple mitre tactics."
    severity = "Medium"

  events:
    $principal_user = $d.detection.detection.outcomes["principal_users"]
    $tactic = $d.detection.detection.rule_labels["tactic"]
    $rule_name = $d.detection.detection.rule_name

  match:
    $principal_user over 48h

  outcome:
    $mitre_tactics_count = count_distinct($tactic)
    $mitre_tactics = array_distinct($d.detection.rule_labels["tactic"])
    $risk_score = min(100, (50+15*$mitre_tactics_count))
    $upstream_rules = array_distinct($rule_name)

  condition:
    $d and $mitre_tactics_count > 1
}

```

### Sequential composite detections

Sequential composite detections identify patterns of related events where the
sequence of detections is important, such as a brute-force login attempt
detection, followed by a successful login. These patterns can involve multiple
base detections or a combination of base detections and events.

```
rule composite_bruteforce_login {
  meta:
    rule_name = "Bruteforce Login Composite"
    author = "Google Cloud Security"
    description = "Detects when an IP address associated with a Workspace brute force attempt successfully logs in"
    severity = "High"

  events:
    $bruteforce_detection.detection.detection.rule_name = /Workspace Anomalous Failed Logins/
    $bruteforce_ip = $d.detection.detection.outcomes["principal_ips"]

    $login_event.metadata.product_name = "login"
    $login_event.metadata.product_event_type = "login_success"
    $login_event.metadata.vendor_name = "Google Workspace"
    $login_ip = $login_event.principal.ip

    // Ensure the brute force detection and successful login occurred from the same IP
    $login_ip = $bruteforce_ip

    $target_account = $login_event.target.user.email_addresses

    // Ensure the brute force detection occurred before the successful login
    $bruteforce_detection.detection.detection_time.seconds < $login_event.metadata.event_timestamp.seconds

  match:
    $bruteforce_ip over 24h

  outcome:
    $risk_score = 90
    $principal_users = array_distinct($target_account)

  condition:
    $bruteforce_detection and $login_event
}


```

#### Context-aware detections

Context-aware composite detections enrich detections with additional context,
such as IP addresses found in threat feeds.

```
rule composite_tor_enrichment {
  meta:
    rule_name = "Detection with IP from TOR Feed"
    author = "Google Cloud Security"
    description = "Adds additional context from the TOR intel feed to detections"
    severity = "High"

  events:
    $detection_ip = $d.detection.detection.outcomes["principal_ips"]
    $gcti.graph.metadata.entity_type = "IP_ADDRESS"
    $gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"
    $gcti_feed.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $gcti.graph.metadata.product_name = "GCTI Feed"
    $gcti.graph.metadata.threat.threat_feed_name = "Tor Exit Nodes"

    $detection_ip = $gcti.graph.entity.ip

    $rule_name = $d.detection.detection.rule_name
    $risk = $d.detection.detection.outcomes["risk_score"]

  match:
    $detection_ip, $rule_name over 1h

  outcome:
    $risk_score = 80
    $upstream_rule = array_distinct($rule_name)

  condition:
    $d and $gcti
}

```

#### Co-occurrence detections

Co-occurrence composite detections are a form of aggregation that can detect a
combination of related events, such as a combination of privilege escalation
and data exfiltration detections triggered by a user.

```
rule composite_privesc_exfil_sequential {
  meta:
    rule_name = "Privilege Escalation and Exfiltration Composite"
    author = "Google Cloud Security"
    description = "Looks for a detection sequence of privilege escalation followed by exfiltration."
    severity = "High"

  events:
    $privilege_escalation.detection.detection.rule_labels["tactic"] = "TA0004"
    $exfiltration.detection.detection.rule_labels["tactic"] = "TA0010"

    $pe_user = $privilege_escalation.detection.detection.outcomes["principal_users"]
    $ex_user = $exfiltration.detection.detection.outcomes["principal_users"]

    $pe_user = $ex_user

  match:
    $pe_user over 48h

  outcome:
    $risk_score = 75
    $privesc_rules = array_distinct($privilege_escalation.detection.detection.rule_name)
    $exfil_rules = array_distinct($exfiltration.detection.detection.rule_name)

  condition:
    $privilege_escalation and $exfiltration
}

```

### Sliding window rule example

The following YARA-L 2.0 sliding window example searches for the absence of
`firewall_2` events after `firewall_1` events. The `after` keyword is used with
the pivot event variable `$e1` to specify that only 10 minute windows after each
`firewall_1` event should be checked when correlating events.

```
rule SlidingWindowRuleExample {
  meta:
    author = "alice@example.com"

  events:
    $e1.metadata.product_name = "firewall_1"
    $e1.principal.hostname = $host

    $e2.metadata.product_name = "firewall_2"
    $e2.principal.hostname = $host

  match:
    $host over 10m after $e1

  condition:
    $e1 and !$e2
}

```

### Zero value exclusion example

Rules Engine implicitly filters out the zero values for all placeholders
that are used in the `match` section.
For more information, see [zero value handling in the `match` section](/chronicle/docs/detection/yara-l-2-0-syntax#zero_value_handling_in_the_match_section).
This can be disabled by using the `allow_zero_values` option as
described in [allow\_zero\_values](/chronicle/docs/detection/yara-l-2-0-syntax#allow_zero_values).

However, for other referenced event fields,
zero values are not excluded unless you explicitly specify such conditions.

```
rule ExcludeZeroValues {
  meta:
    author = "alice@example.com"

  events:
    $e1.metadata.event_type = "NETWORK_DNS"
    $e1.principal.hostname = $hostname

    // $e1.principal.user.userid may be empty string.
    $e1.principal.user.userid != "Guest"

    $e2.metadata.event_type = "NETWORK_HTTP"
    $e2.principal.hostname = $hostname

    // $e2.target.asset_id cannot be empty string as explicitly specified.
    $e2.target.asset_id != ""

  match:
    // $hostname cannot be empty string. The rule behaves as if the
    // predicate, `$hostname != ""` was added to the events section, because
    // `$hostname` is used in the match section.
    $hostname over 1h

  condition:
    $e1 and $e2
}

```

### Rule with `outcome` section example

You can add the optional `outcome` section in a YARA-L 2.0 rule to extract
additional information of each detection. In the condition section, you can also specify
conditionals on outcome variables. You can use the `outcome` section of a detection
rule to set variables for downstream consumption. For example, you can set a
severity score based on data from the events being analyzed.

For more information, see the following:

* [Outcome section syntax](/chronicle/docs/detection/yara-l-2-0-syntax#outcome_section_syntax)
* [Outcome conditionals syntax](/chronicle/docs/detection/yara-l-2-0-syntax#outcome_conditionals)
* [Overview of the `outcome` section](/chronicle/docs/detection/context-aware-analytics#outcome_section)

#### Multi-event rule with outcome section:

The following rule looks at two events to get the value of
`$hostname`. If the value of `$hostname` matches over a 5-minute period,
then a severity score is applied. When including a time period in the `match` section,
the rule checks within the specified time period.

```
rule OutcomeRuleMultiEvent {
    meta:
      author = "Google Cloud Security"
    events:
      $u.udm.principal.hostname = $hostname
      $asset_context.graph.entity.hostname = $hostname

      $severity = $asset_context.graph.entity.asset.vulnerabilities.severity

    match:
      $hostname over 5m

    outcome:
      $risk_score =
        max(
            100
          + if($hostname = "my-hostname", 100, 50)
          + if($severity = "HIGH", 10)
          + if($severity = "MEDIUM", 5)
          + if($severity = "LOW", 1)
        )

      $asset_id_list =
        array(
          if($u.principal.asset_id = "",
             "Empty asset id",
             $u.principal.asset_id
          )
        )

      $asset_id_distinct_list = array_distinct($u.principal.asset_id)

      $asset_id_count = count($u.principal.asset_id)

      $asset_id_distinct_count = count_distinct($u.principal.asset_id)

    condition:
      $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")
}


```

```
rule OutcomeRuleMultiEvent {
    meta:
      author = "alice@example.com"
    events:
      $u.udm.principal.hostname = $hostname
      $asset_context.graph.entity.hostname = $hostname

      $severity = $asset_context.graph.entity.asset.vulnerabilities.severity

    match:
      $hostname over 5m

    outcome:
      $total_network_bytes = sum($u.network.sent_bytes) + sum($u.network.received_bytes)

      $risk_score = if(total_network_bytes > 1024, 100, 50) + 
        max(
          if($severity = "HIGH", 10)
          + if($severity = "MEDIUM", 5)
          + if($severity = "LOW", 1)
        )

      $asset_id_list =
        array(
          if($u.principal.asset_id = "",
             "Empty asset id",
             $u.principal.asset_id
          )
        )

      $asset_id_distinct_list = array_distinct($u.principal.asset_id)

      $asset_id_count = count($u.principal.asset_id)

      $asset_id_distinct_count = count_distinct($u.principal.asset_id)

    condition:
      $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")
}

```

#### Single-event rule with outcome section:

```
rule OutcomeRuleSingleEvent {
    meta:
        author = "alice@example.com"
    events:
        $u.metadata.event_type = "FILE_COPY"
        $u.principal.file.size = $file_size
        $u.principal.hostname = $hostname

    outcome:
        $suspicious_host = $hostname
        $admin_severity = if($u.principal.userid in %admin_users, "SEVERE", "MODERATE")
        $severity_tag = if($file_size > 1024, $admin_severity, "LOW")

    condition:
        $u
}

```

#### Refactoring a multi-event outcome rule into a single-event outcome rule.

You can use the `outcome` section for both single-event rules (rules without a
`match` section), and multi-event rules (rules with a `match` section).
If you previously designed a rule to be multi-event just so you could
use the outcome section, you can optionally refactor those rules by deleting
the `match` section to improve performance. Be aware that because your rule no
longer has a `match` section that applies grouping,
you might receive more detections. This refactor is only
possible for rules that use one event variable as shown in the
following example.

Multi-event outcome rule which uses only one event variable (a
good candidate for a refactor):

```
rule OutcomeMultiEventPreRefactor {
    meta:
      author = "alice@example.com"
      description = "Outcome refactor rule, before the refactor"

    events:
      $u.udm.principal.hostname = $hostname

    match:
      $hostname over 5m

    outcome:
      $risk_score = max(if($hostname = "my-hostname", 100, 50))

    condition:
      $u
}

```

You can refactor the rule by deleting the `match` section. Note that you
must also remove the aggregate in the `outcome` section since the rule will now be
single-event. For more information on aggregations, see [outcome aggregations](/chronicle/docs/detection/yara-l-2-0-syntax#aggregations).

```
rule OutcomeSingleEventPostRefactor {
    meta:
      author = "alice@example.com"
      description = "Outcome refactor rule, after the refactor"

    events:
      $u.udm.principal.hostname = $hostname

    // We deleted the match section.

    outcome:
      // We removed the max() aggregate.
      $risk_score = if($hostname = "my-hostname", 100, 50)

    condition:
      $u
}

```

### Function to placeholder rule example

You can assign a placeholder variable to the result of a function call and
can use the placeholder variable in other sections of the rule, such as the
`match` section, `outcome` section, or `condition` section. See the following example:

```
rule FunctionToPlaceholderRule {
    meta:
      author = "alice@example.com"
      description = "Rule that uses function to placeholder assignments"

    events:
        $u.metadata.event_type = "EMAIL_TRANSACTION"

        // Use function-placeholder assignment to extract the
        // address from an email.
        // address@website.com -> address
        $email_to_address_only = re.capture($u.network.email.from , "(.*)@")

        // Use function-placeholder assignment to normalize an email:
        // uid@??? -> uid@company.com
        $email_from_normalized = strings.concat(
            re.capture($u.network.email.from , "(.*)@"),
            "@company.com"
        )

        // Use function-placeholder assignment to get the day of the week of the event.
        // 1 = Sunday, 7 = Saturday.
        $dayofweek = timestamp.get_day_of_week($u.metadata.event_timestamp.seconds)

    match:
        // Use placeholder (from function-placeholder assignment) in match section.
        // Group by the normalized from email, and expose it in the detection.
        $email_from_normalized over 5m

    outcome:
        // Use placeholder (from function-placeholder assignment) in outcome section.
        // Assign more risk if the event happened on weekend.
        $risk_score = max(
            if($dayofweek = 1, 10, 0) +
            if($dayofweek = 7, 10, 0)
        )

    condition:
        // Use placeholder (from function-placeholder assignment) in condition section.
        // Match if an email was sent to multiple addresses.
        #email_to_address_only > 1
}

```

### Outcome conditionals example rule

In the `condition` section, you can use outcome variables that were defined
in the `outcome` section. The following example demonstrates how to filter on
risk scores to reduce noise in detections by using outcome conditionals.

```
rule OutcomeConditionalRule {
    meta:
        author = "alice@example.com"
        description = "Rule that uses outcome conditionals"

    events:
        $u.metadata.event_type = "FILE_COPY"
        $u.principal.file.size = $file_size
        $u.principal.hostname = $hostname

        // 1 = Sunday, 7 = Saturday.
        $dayofweek = timestamp.get_day_of_week($u.metadata.collected_timestamp.seconds)

    outcome:
        $risk_score =
            if($file_size > 500*1024*1024, 2) + // Files 500MB are moderately risky
            if($file_size > 1024*1024*1024, 3) + // Files over 1G get assigned extra risk
            if($dayofweek=1 or $dayofweek=7, 4) + // Events from the weekend are suspicious
            if($hostname = /highly-privileged/, 5) // Check for files from highly privileged devices

    condition:
        $u and $risk_score >= 10
}


```

Last updated 2025-06-05 UTC.

