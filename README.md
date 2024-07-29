# Custom Analytics Rules
Custom analytics rules to be used in Microsoft Sentinel. Assuming that you have the proper connectors in place to gather data, these can provide insight and alerting to your SOC. 

## Updated - Successful logon from IP and failure from a different IP
While useful for monitoring users and ensuring that a token was not possibly stolen or screen recording conducted from across the world, this has historically been a nuisance alert due to not working with IPv6 IPs, causing headache to SOC Teams. This has been updated to work with IPv6 IPs: 

Rule query:
```
let logonDiff = 10m;
let aadFunc = (tableName: string) {
table(tableName)
| where ResultType == "0"
| where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online")
| project SuccessLogonTime = TimeGenerated, UserPrincipalName, SuccessIPAddress = IPAddress, AppDisplayName, SuccessIPBlock = strcat(split(IPAddress, ".")[0], ".", split(IPAddress, ".")[1]), Type
| join kind= inner (
    table(tableName)
    | where ResultType !in ("0", "50140", "50173", "50076", "50089", "70044")
    | where ResultDescription !~ "Other"
    | where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online")
    | project FailedLogonTime = TimeGenerated, UserPrincipalName, FailedIPAddress = IPAddress, AppDisplayName, ResultType, ResultDescription, Type
) on UserPrincipalName, AppDisplayName
| where SuccessLogonTime < FailedLogonTime and FailedLogonTime - SuccessLogonTime <= logonDiff and FailedIPAddress !startswith SuccessIPBlock and FailedIPAddress != SuccessIPAddress
| summarize FailedLogonTime = max(FailedLogonTime), SuccessLogonTime = max(SuccessLogonTime) by UserPrincipalName, SuccessIPAddress, AppDisplayName, FailedIPAddress, ResultType, ResultDescription, Type
| extend timestamp = SuccessLogonTime
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
```
Other configuration options can be left as default. 

## >20 Failed Interactive Logins
As the name implies, this is to monitor for when brute forcing causes a significant number of failed logins in a given day. While 20 has historically worked for me to balance nuisance and unseen alerts, you may want to tune this for your customer or tenant situation. 

Rule query:
```
SigninLogs
| where  ResultType !in ("0", "50140", "50173", "50076", "50089", "70044","50074","500121")
| where UserType == "Member"
| where IsInteractive == true
| summarize IPlist = make_set(IPAddress), FailedSignInCount = count() by tostring(UserPrincipalName)
| where FailedSignInCount > 20
| project UserPrincipalName, FailedSignInCount, IPlist
```

Other Configurations:

![image](https://github.com/user-attachments/assets/569098f9-0046-46d7-9fd4-05328beb78d0)
