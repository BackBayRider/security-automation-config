#!/usr/bin/env bash
# This is a script to post alerts about new Dependency-Check
# findings to the community server

max_post_length=16383

# Get artifacts from CircleCI
report_artifacts=$(curl -s https://circleci.com/api/v1.1/project/gh/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/$CIRCLE_BUILD_NUM/artifacts)
json_url=$(echo $report_artifacts | jq -r 'map(select(.path == "Reports/OWASP/dependency-check-report.json").url)[0]')
json_report=$(curl -sL $json_url)

# Anything new?
vulnerability_count=$(echo $json_report | jq '[.dependencies[]?.vulnerabilities[]?.name]|length')
if [ $vulnerability_count -ne 0 ]
then
  if [ $vulnerability_count -gt 1 ]
  then
    alert_message_header="$vulnerability_count new findings"
  else
    alert_message_header="New finding"
  fi
  alert_message_header="$alert_message_header in \`$CIRCLE_PROJECT_REPONAME\` CircleCI build [#$CIRCLE_BUILD_NUM]($CIRCLE_BUILD_URL)"
  if [ -z "$CIRCLE_PULL_REQUEST" ]
  then
    alert_message_header="$alert_message_header\n\n"
  else
    alert_message_header="$alert_message_header, triggered by $CIRCLE_PULL_REQUEST\n\n"
  fi
  alert_message="$alert_message_header|Dependency|CPEs|CVEs|Severity|\n|----------|----|----|--------|\n"
  html_url=$(echo $report_artifacts | jq -r 'map(select(.path == "Reports/OWASP/dependency-check-report.html").url)[0]')

  # Build the rows of the summary table
  vulnerable_dependencies=($(echo $json_report | jq -r '[.dependencies[]?]|map(select(.vulnerabilities).fileName)[]'))
  index_of_name=0
  for dependency in ${vulnerable_dependencies[@]}
  do
    # In case there are multiple dependencies with the same fileName, process them in order
    json_dependencies=$(echo $json_report | jq -r '[.dependencies[]?]|map(select(.fileName=="'$dependency'"))')
    json_dependency=$(echo $json_dependencies | jq -r '.['$index_of_name']')
    if [ $((++index_of_name)) -ge $(echo $json_dependencies | jq -r length) ]
    then
      index_of_name=0
    fi

    index=$(echo $json_report | jq '[.dependencies[]?]|map(.fileName)|index("'$dependency'")+1')
    sha1=$(echo $json_dependency | jq -r '.sha1')
    # The SHA-1 is set on the JSON report only for non-virtual dependencies
    # Calculation for virtual dependencies is analyzer-specific
    if [ "$sha1" = 'null' ]
    then
      evidence_source=$(echo $json_dependency | jq -r '.evidenceCollected|.vendorEvidence+.productEvidence+.versionEvidence|map(.source)|unique[0]')
      if [ "$evidence_source" = 'Gopkg.lock' ]
      then
        sha1=($(echo $json_dependency | jq -r '.packages[0].id' | tr -d '\n' | sha1sum))
      else
        sha1=($(echo $json_dependency | jq -r '.filePath' | tr -d '\n' | sha1sum))
      fi
    fi
    dependency_url="$html_url#l${index}_$sha1"
    cpes=$(echo $json_dependency | jq -r '.vulnerabilityIds|select(.)|map("`"+.id+"`")|join(", ")')
    cves=$(echo $json_dependency | jq -r '.vulnerabilities|select(.)|map("[`"+.name+"`](http://web.nvd.nist.gov/view/vuln/detail?vulnId="+.name+")")|join(", ")')
    severities=$(echo $json_dependency | jq '.vulnerabilities|select(.)|map(.severity)|unique')
    severity=$(echo $severities | jq -r 'if contains(["HIGH"]) then "`HIGH`" elif contains(["MEDIUM"]) then "`MEDIUM`" elif contains(["LOW"]) then "`LOW`" else "`Unknown`" end')
    alert_message="$alert_message|[$dependency]"'('$dependency_url')'"|$cpes|$cves|$severity|\n"
  done
  alert_message_footer='\nView the full report [here]('$html_url')'
  alert_message_footer=$alert_message_footer' or [edit suppressions](https://github.com/mattermost/security-automation-config/edit/master/dependency-check/suppression.'$CIRCLE_PROJECT_REPONAME'.xml).'

  alert_message=$alert_message$alert_message_footer

  if [ $(echo $alert_message | wc -c) -ge $max_post_length ]
  then
    alert_message=$alert_message_header'---\n**Summary table exceeds maximum post length and has been omitted.**\n\n---'$alert_message_footer
  fi

  # Post to Mattermost
  if [ -z "$SAST_WEBHOOK_URL" ]
  then
    echo -e $alert_message
  else
    curl -s -X POST -d 'payload={"username": "Dependency-Check", "icon_url": "https://www.mattermost.org/wp-content/uploads/2016/04/icon.png", "text":
      "'"$alert_message"'"
      }' "$SAST_WEBHOOK_URL"
  fi
fi