## **Working with AWS CloudTrail**

## **Overview**

In this lab, I investigated a security breach on the Café web application hosted on an Amazon EC2 instance. Using AWS CloudTrail, I tracked down who modified the web server’s security group, identified the hacker (“chaos-user”), and implemented remediation measures to secure both the AWS account and EC2 instance.

## **Objectives & Learning Outcomes**

By completing this lab, I learned how to:

Configure a CloudTrail trail to capture AWS API actions

Analyze CloudTrail logs using grep and AWS CLI

Query CloudTrail data using Amazon Athena

Identify unauthorized access and determine who made which changes

Remediate security vulnerabilities and remove malicious users

## **Architecture Diagram**

Architecture Summary:

Café Web Server (EC2) hosts the website

AWS CloudTrail records all API calls into S3 bucket (monitoring####)

Amazon Athena queries CloudTrail logs stored in S3

IAM manages user access (the chaos-user exploited IAM access)

SSH access through Security Group (modified by attacker)

Diagram:


## **Commands & Steps**
```bash
# -----------------------
# TASK 1: VERIFY WEBSITE
# -----------------------
# View EC2 Instance details
aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,Tags]" --output table

# -----------------------
# TASK 2: CREATE CLOUDTRAIL TRAIL
# -----------------------
aws cloudtrail create-trail \
  --name monitor \
  --s3-bucket-name monitoring1234 \
  --is-multi-region-trail

aws cloudtrail start-logging --name monitor

# -----------------------
# TASK 3: ANALYZE LOGS WITH GREP
# -----------------------
mkdir ctraillogs
cd ctraillogs
aws s3 ls
aws s3 cp s3://monitoring1234/ . --recursive
gunzip *.gz

# Examine structure of log file
cat <filename.json> | python -m json.tool

# Filter by sourceIPAddress
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep sourceIPAddress ; done

# Filter by eventName
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep eventName ; done

# Identify region and security group
region=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | cut -d '"' -f4)
sgId=$(aws ec2 describe-instances --filters "Name=tag:Name,Values='Cafe Web Server'" \
  --query 'Reservations[*].Instances[*].SecurityGroups[*].[GroupId]' --region $region --output text)
echo $sgId

# Narrow CloudTrail search by Security Group
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup \
  --region $region --output text | grep $sgId

# -----------------------
# TASK 4: QUERY USING ATHENA
# -----------------------
# Athena table creation sample
SELECT * FROM cloudtrail_logs_monitoring---- LIMIT 5;

# Filter results
SELECT useridentity.userName, eventtime, eventsource, eventname, requestparameters
FROM cloudtrail_logs_monitoring----
WHERE eventsource = 'ec2.amazonaws.com'
AND eventname LIKE '%Security%'
LIMIT 50;

# Identify active users in last 24h
SELECT DISTINCT useridentity.userName, eventName, eventSource
FROM cloudtrail_logs_monitoring-----
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now())
ORDER BY eventSource;

# -----------------------
# TASK 5: REMOVE CHAOS-USER
# -----------------------
sudo aureport --auth
who
sudo userdel -r chaos-user || true
sudo kill -9 <ProcNum>
sudo userdel -r chaos-user
sudo cat /etc/passwd | grep -v nologin

# Fix SSH config
sudo vi /etc/ssh/sshd_config
# Comment out "PasswordAuthentication yes"
# Uncomment "PasswordAuthentication no"
sudo service sshd restart

# Remove open port 22 rule
aws ec2 revoke-security-group-ingress \
  --group-id $sgId --protocol tcp --port 22 --cidr 0.0.0.0/0

# Restore hacked image
cd /var/www/html/cafe/images/
sudo mv Coffee-and-Pastries.backup Coffee-and-Pastries.jpg

# Delete hacker IAM user
aws iam delete-user --user-name chaos

```

## **Screenshots**

CloudTrail_Trail_Created.png	Proof of “monitor” trail successfully created

Hacked_Website.png	Modified Café website with hacked image

Athena_Query_Results.png	SQL query revealing “chaos-user” modifying security group

ChaosUser_Removed.png	Terminal confirmation of user deletion

Restored_Website.png	Verified website restored with correct image

## **Tools Used**

Amazon CloudTrail – recorded API activity

Amazon S3 – stored log files

AWS CLI & Linux Commands – analyzed JSON logs

Amazon Athena – SQL-based log analysis

IAM – controlled and revoked user access

Amazon EC2 – hosted Café web server

## **Key Takeaways**

CloudTrail is the forensic backbone of AWS environments.

Log analysis via CLI + Athena enables pinpointing exact users and timestamps.

Security misconfigurations (e.g., open SSH port 22) can be easily exploited.

Enforcing IAM least privilege and disabling password login are critical.

Combining Athena + CloudTrail = fast, SQL-based incident response.

## **What Actually Happened**

The Café website looked normal at first.

After enabling CloudTrail, the website displayed a hacked image.

CloudTrail logs showed an extra SSH rule (0.0.0.0/0) added to the EC2 Security Group.

Using grep and Athena queries, I identified user "chaos" as the one who performed the AuthorizeSecurityGroupIngress event.

I SSH’d into the server and confirmed an OS user chaos-user was logged in.

The user was forcibly disconnected (sudo kill -9), deleted, and SSH password authentication disabled.

The original Café image was restored.

Finally, I deleted the IAM user chaos to prevent further intrusion.

## **Author**
Amarachi Emeziem

Cloud Engineer/Security

LinkedIn Profile: https://www.linkedin.com/in/amarachilemeziem/
