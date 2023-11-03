# maven-project

Simple Maven Project


S.No	Query Title	Description	Query

1	Azure DevOps- Project visibility changed to public	This hunting query identifies Azure DevOps activities where organization project visibility changed to public project	
AzureDevOpsAuditing
| where Area == "Project"
| where OperationName == "Project.UpdateVisibilityCompleted"
| where Data.PreviousProjectVisibility == "private"
| where Data.ProjectVisibility == "public"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress

2	Azure DevOps - New Package Feed Created	An attacker could look to introduce upstream compromised software packages by creating a new package feed within Azure DevOps. This query looks for new Feeds and includes details on any Azure AD Identity Protection alerts related to the user account creating the feed to assist in triage	let alert_threshold = 0;
AzureDevOpsAuditing
| where OperationName matches regex "Artifacts.Feed.(Org|Project).Create"
| extend FeedName = tostring(Data.FeedName)
| extend FeedId = tostring(Data.FeedId)
| join kind = leftouter (
SecurityAlert
| where ProviderName == "IPC"
| extend AadUserId = tostring(parse_json(Entities)[0].AadUserId)
| summarize Alerts=count() by AadUserId) on $left.ActorUserId == $right.AadUserId
| extend Alerts = iif(isempty(Alerts), 0, Alerts)
| project-reorder TimeGenerated, Details, ActorUPN, IpAddress, UserAgent
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress

3	Azure DevOps Pull Request Policy Bypassing	Looks for users bypassing Update Policies in repos	
AzureDevOpsAuditing
| where OperationName == 'Git.RefUpdatePoliciesBypassed'
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress

4	Azure DevOps - New Release Pipeline Created	An attacker could look to create a new poisoned pipeline in Azure DevOps and attack a build process to it. This hunting query looks for new pipelines being created in projects where the creating user has not been seen creating a pipeline before. This query could have a significant false positive rate and records should be triaged to determine if a user creating a pipeline is authorized and expected.	

let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = 30d;
// Set the period for detections
// Get a list of previous Release Pipeline creators to exclude
let releaseusers = AzureDevOpsAuditing
| where TimeGenerated between(ago(lookback)..starttime)
| where OperationName =~ "Release.ReleasePipelineCreated"
// We want to look for users performing actions in specific organizations so we creat this userscope object to match on
| extend UserScope = strcat(ActorUPN, "-", ProjectName)
| summarize by UserScope;
// Get Release Pipeline creations by new users
AzureDevOpsAuditing
| where TimeGenerated between(starttime..endtime)
| where OperationName =~ "Release.ReleasePipelineCreated"
| extend UserScope = strcat(ActorUPN, "-", ProjectName)
| where UserScope !in (releaseusers)
| extend ActorUPN = tolower(ActorUPN)
| project-away Id, ActivityId, ActorCUID, ScopeId, ProjectId, TenantId, SourceSystem, UserScope
// See if any of these users have Azure AD alerts associated with them in the same timeframe
| join kind = leftouter (
SecurityAlert
| where TimeGenerated between(starttime..endtime)
| where ProviderName == "IPC"
| extend AadUserId = tostring(parse_json(Entities)[0].AadUserId)
| summarize Alerts=count() by AadUserId) on $left.ActorUserId == $right.AadUserId
| project-reorder TimeGenerated, ProjectName, Details, ActorUPN, IpAddress, UserAgent, Alerts
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress

5	Azure DevOps - Internal Upstream Package Feed Added.	An attacker aiming to insert malicious code into a build process could look to introduce compromised upstream packages into the build process. Looking at internal packages can have a significant false positive rate compared to looking at external feeds so running this as a hunting query at least initially is advised. If an environment has low number of events it can be upgraded to a detection.

let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = totimespan((endtime-starttime)*10);
// Add any known allowed sources and source locations to the filter below.
let allowed_sources = dynamic([]);
let allowed_locations = dynamic([]);
let known_packages = (
AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < starttime
// Look for feeds created or modified at either the organization or project level
| where OperationName matches regex "Artifacts.Feed.(Org|Project).Modify"
| where Details has "UpstreamSources, added"
| extend UpstreamsAdded = Data.UpstreamsAdded
// As multiple feeds may be added expand these out
| mv-expand UpstreamsAdded
// Only focus on internal feeds
| where UpstreamsAdded.UpstreamSourceType =~ "internal"
| extend SourceLocation = tostring(UpstreamsAdded.Location)
| summarize by SourceLocation);
// Look for internal feeds being added from a new location
AzureDevOpsAuditing
| where TimeGenerated between(starttime..endtime)
| where OperationName matches regex "Artifacts.Feed.(Org|Project).Modify"
| where Details has "UpstreamSources, added"
| extend FeedName = tostring(Data.FeedName)
| extend FeedId = tostring(Data.FeedId)
| extend UpstreamsAdded = Data.UpstreamsAdded
// As multiple feeds may be added expand these out
| mv-expand UpstreamsAdded
// Only focus on internal feeds
| where UpstreamsAdded.UpstreamSourceType =~ "internal"
| extend SourceLocation = tostring(UpstreamsAdded.Location)
| extend SourceName = tostring(UpstreamsAdded.Name)
// Exclude sources and locations in the allow list
| where SourceLocation !in (known_packages)
| where SourceLocation !in (allowed_locations) and SourceName !in (allowed_sources)
| extend SourceProtocol = tostring(UpstreamsAdded.Protocol)
| extend SourceStatus = tostring(UpstreamsAdded.Status)
| project-reorder TimeGenerated, OperationName, ScopeDisplayName, ProjectName, FeedName, SourceName, SourceLocation, SourceProtocol, ActorUPN, UserAgent, IpAddress
// See if there are details of who created this feed and when to add context
| join kind=leftouter (AzureDevOpsAuditing
| where TimeGenerated > ago(lookback)
| where OperationName matches regex "Artifacts.Feed.(Org|Project).Create"
| extend FeedId = tostring(Data.FeedId)
| project FeedId, FeedCreatedBy=ActorUPN, TimeCreated=TimeGenerated) on FeedId, $left.ActorUPN==$right.FeedCreatedBy
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


6	Azure DevOps- Addtional Org Admin added	This hunting query identifies Azure DevOps activities where additional organization admin is added

AzureDevOpsAuditing
| where OperationName == "Group.UpdateGroupMembership.Add"
| where Category == "Modify"
| where Area == "Group"
| where Details contains ("Project Collection Administrators")
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


7	Azure DevOps- Public project created	This hunting query identifies Azure DevOps activities where a public project is created

AzureDevOpsAuditing
| where Data.ProjectVisibility == "Public"
| where OperationName == "Project.CreateCompleted"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


8	Azure DevOps- Guest users access enabled	This hunting query identifies Azure DevOps activities where organization Guest Access policy is enabled by the admin

AzureDevOpsAuditing
| where OperationName =="OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.DisallowAadGuestUserAccess"
| where Data.PolicyValue == "OFF"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


9	Azure DevOps - Variable Created and Deleted	Variables can be used at various stages of a pipeline to inject static variables. Depending on the build process these variables could be added by an attacker to get a build process to conduct an unwanted action such as communicating with an attacker-controlled endpoint or injecting values into code. This query looks for variables that are added and then deleted in a short space of time. This is not normal expected behavior and could ben an indicator of attacker creating elements and then covering tracks. If this hunting query produces only a small number of events in an environment it could be promoted to a detection.

AzureDevOpsAuditing
| where OperationName =~ "Library.VariableGroupModified"
| extend variables = Data.Variables
| extend VariableGroupName = tostring(Data.VariableGroupName)
| join (AzureDevOpsAuditing
| where OperationName =~ "Library.VariableGroupModified"
| extend variables = Data.Variables
| extend VariableGroupName = tostring(Data.VariableGroupName)) on VariableGroupName
| extend len = array_length(bag_keys(variables))
| extend len1 = array_length(bag_keys(variables1))
| where (TimeGenerated < TimeGenerated1 and len > len1) or (TimeGenerated1 > TimeGenerated and len1 < len)
| project-away len, len1
| extend VariablesRemoved = set_difference(bag_keys(variables), bag_keys(variables1))
| project-rename TimeCreated=TimeGenerated, TimeDeleted = TimeGenerated1, CreatingUser = ActorUPN, DeletingUser = ActorUPN1, CreatingIP = IpAddress, DeletingIP = IpAddress1, CreatingUA = UserAgent, DeletingUA = UserAgent1
| project-reorder VariableGroupName, TimeCreated, TimeDeleted, VariablesRemoved, CreatingUser, CreatingIP, CreatingUA, DeletingUser, DeletingIP, DeletingUA
| extend timestamp = TimeDeleted, AccountCustomEntity = DeletingUser, IPCustomEntity = DeletingIP


10	Azure DevOps Display Name Changes	Shows all users with more than 1 display name in recent history. This is to hunt for users maliciously changing their display name as a masquerading technique

AzureDevOpsAuditing
| where ActorCUID != '00000000-0000-0000-0000-000000000000' and ActorDisplayName != "Azure DevOps User"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DisplayNameCount = dcount(ActorDisplayName), ActorDisplayNames = make_set(ActorDisplayName), make_set(IpAddress), make_set(ProjectName) by ActorCUID, ActorUPN
| where DisplayNameCount > 1
| extend timestamp = StartTime, AccountCustomEntity = ActorUPN


11	Azure DevOps - New Release Approver	Releases in Azure Pipelines often require a user authorization to perform the release. An attacker that has compromised a build may look to self-approve a release using a compromised account to avoid user focus on that release. This query looks for release approvers in pipelines where they have not approved a release in the last 30 days. This query can have a significant false positive rate so its best suited as a hunting query rather than a detection.

let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = 30d;
AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < starttime
| where OperationName in ("Release.ApprovalCompleted", "Release.ApprovalsCompleted")
| extend PipelineName = tostring(Data.PipelineName)
| extend ApprovalType = tostring(Data.ApprovalType)
| extend StageName = tostring(Data.StageName)
| extend ReleaseName = tostring(Data.ReleaseName)
| summarize by PipelineName, ActorUPN, ApprovalType
| join kind=rightanti (
AzureDevOpsAuditing
| where TimeGenerated between(starttime..endtime)
| where OperationName in ("Release.ApprovalCompleted", "Release.ApprovalsCompleted")
| extend PipelineName = tostring(Data.PipelineName)
| extend ApprovalType = tostring(Data.ApprovalType)
| extend StageName = tostring(Data.StageName)
| extend ReleaseName = tostring(Data.ReleaseName)) on ActorUPN
| project-reorder TimeGenerated, PipelineName, ActorUPN, ApprovalType, StageName, ReleaseName, IpAddress, UserAgent, AuthenticationMechanism
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


12	Azure DevOps- AAD Conditional Access Disabled	This hunting query identifies Azure DevOps activities where organization AADConditionalAccess policy disable by the admin

AzureDevOpsAuditing
| where OperationName =="OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.EnforceAADConditionalAccess"
| where Data.PolicyValue == "OFF"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


13	Azure DevOps - New PAT Operation	PATs are typically used for repeated, programmatic tasks. This query looks for PATs based authentication being used with an Operation not previous associated with PAT based authentication. This could indicate an attacker using a stolen PAT to perform malicious actions.

let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = totimespan((endtime-starttime)*10);
let PAT_Actions = AzureDevOpsAuditing
| where TimeGenerated > ago(lookback) and TimeGenerated < starttime
| where AuthenticationMechanism startswith "PAT"
| summarize by OperationName;
AzureDevOpsAuditing
| where TimeGenerated between(starttime..endtime)
| where AuthenticationMechanism startswith "PAT"
| where OperationName !in (PAT_Actions)
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


14	Azure DevOps - New Agent Pool Created	Agent Pools provide a valuable resource to build processes. Creating and using a compromised agent pool in a pipeline could allow an attacker to compromise a build process. Whilst the creation of an agent pool itself is not malicious it is unlike to occur so often that it cannot be used as a hunting element when focusing on Azure DevOps activity.

AzureDevOpsAuditing
| where OperationName =~ "Library.AgentPoolCreated"
| extend AgentPoolName = tostring(Data.AgentPoolName)
| extend AgentPoolId = tostring(Data.AgentPoolId)
| extend IsHosted = tostring(Data.IsHosted)
| extend IsLegacy = tostring(Data.IsLegacy)
| project-reorder TimeGenerated, ActorUPN, UserAgent, IpAddress, AuthenticationMechanism, OperationName, AgentPoolName, IsHosted, IsLegacy, Data
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


15	Azure DevOps - Build Deleted After Pipeline Modification	An attacker altering pipelines may look to delete builds to reduce the footprint they leave on a system. This query looks for a build for a pipline being deleted within 1 hour of a pipeline being modified. This event may produce false positives but should not be so common that it can't be effectively used as part of hunting.

AzureDevOpsAuditing
| where OperationName =~ "Release.ReleaseDeleted"
| extend PipelineId = tostring(Data.PipelineId)
| extend PipelineName = tostring(Data.PipelineName)
| extend timekey = bin(TimeGenerated, 1h)
| join (AzureDevOpsAuditing
| where OperationName =~ 'Release.ReleasePipelineModified'
| extend PipelineId = tostring(Data.PipelineId)
| extend PipelineName = tostring(Data.PipelineName)
| extend timekey = bin(TimeGenerated, 1h)) on timekey, PipelineId, ActorUPN
| where TimeGenerated1 < TimeGenerated
| extend ReleaseName = tostring(Data.ReleaseName)
| project-rename TimeModified = TimeGenerated1, TimeDeleted = TimeGenerated, ModifyOperation = OperationName1, ModifyUser=ActorUPN1, ModifyIP=IpAddress1, ModifyUA= UserAgent1, DeleteOperation=OperationName, DeleteUser=ActorUPN, DeleteIP=IpAddress, DeleteUA=UserAgent
| project-reorder TimeModified, ProjectName, PipelineName, ModifyUser, ModifyIP, ModifyUA, TimeDeleted, DeleteOperation, DeleteUser, DeleteIP, DeleteUA,ReleaseName
| extend timestamp = TimeDeleted, AccountCustomEntity = DeleteUser, IPCustomEntity = DeleteIP

16	Azure DevOps - Build Check Deleted.	Build checks can be built into a pipeline in order control the release process, these can include things such as the successful passing of certain steps, or an explicit user approval. An attacker who has altered a build process may look to remove a check in order to ensure a compromised build is released. This hunting query simply looks for all check removal events, these should be relatively uncommon. In the output Type shows the type of Check that was deleted.

AzureDevOpsAuditing
  | where OperationName =~ "CheckConfiguration.Deleted"
  | extend ResourceName = tostring(Data.ResourceName)
  | extend Type = tostring(Data.Type)
  | project-reorder TimeGenerated, OperationName, ResourceName, Type, ActorUPN, IpAddress, UserAgent
  | extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


17	Azure DevOps- Public project enabled by admin	This hunting query identifies Azure DevOps activities where organization public projects policy enabled by the admin

AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.AllowAnonymousAccess"
| where Data.PolicyValue == "ON"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress


18	Project Creation	This creates an alert if there a project created	

AzureDevOpsAuditing
| where OperationName == "Project.CreateQeued"


19	Organization Policy Change (Org-policy-change)	This creates an alert if there is a change in organization policy.	

AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend eventData = Prase_json(Data)
| project ActorUserId, OperationName, Data, eventData.PolicyName, eventData.PolicyValue
