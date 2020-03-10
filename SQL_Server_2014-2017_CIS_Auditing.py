#!/usr/local/bin/python
# coding: latin-1

#Coded by Qais Temeiza

import pyodbc

server = '10.211.55.3,1433'
database = 'master'
username = 'Qais'
password = 'qais1'


cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server}'
                      ';SERVER='+server+
                      ';DATABASE='+database+
                      ';UID='+username+
                      ';PWD='+password)

cursor = cnxn.cursor()

#Kerberos should be configured in order to use Windows Authentication
#cnxn = pyodbc.connect(driver='{ODBC Driver 17 for SQL Server}', server='xx.xx.xx.xx,1433', database='master',trusted_connection='yes')


#Get all databases names and save them in an array
cursor.execute("select name FROM sys.databases;")
row = cursor.fetchone()
dbNames = []

while row:

    dbNames.append(row[0])
    row = cursor.fetchone()

#Get user databases names and save them in an array
cursor.execute("""SELECT name FROM sys.databases
WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb', 'Resource')""")

row = cursor.fetchone()
userdbNames = []

while row:

    userdbNames.append(row[0])
    row = cursor.fetchone()

#Open file in order to start writing the results in it
f = open("results.txt", "w")



####################################### Installation, Updates and Patches ##############################################

#1.1 Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)

#1.2 Ensure Single-Function Member Servers are Used (Not Scored)


########################################### Surface Area Reduction #####################################################

#2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as
int) as value_in_use
FROM sys.configurations
WHERE name = 'Ad Hoc Distributed Queries';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.1:1\n")
else:
    f.write("2.1:0\n")


#2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'clr enabled';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.2:1\n")
else:
    f.write("2.2:0\n")


#2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'cross db ownership chaining';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.3:1\n")
else:
    f.write("2.3:0\n")


#2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Database Mail XPs';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.4:1\n")
else:
    f.write("2.4:0\n")

#2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Ole Automation Procedures';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.5:1\n")
else:
    f.write("2.5:0\n")

#2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote access';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.6:1\n")
else:
    f.write("2.6:0\n")

#2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Scored)
cursor.execute("""
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote admin connections'
AND SERVERPROPERTY('IsClustered') = 0;""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.7:1\n")
else:
    f.write("2.7:0\n")

#2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'scan for startup procs';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.8:1\n")
else:
    f.write("2.8:0\n")

#2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored)
cursor.execute("""SELECT name
FROM sys.databases
WHERE is_trustworthy_on = 1
AND name != 'msdb';""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("2.9:1\n")
else:
    f.write("2.9:0\n")

#2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Not Scored)

#2.11 Ensure SQL Server is configured to use non-standard ports (Not Scored)
cursor.execute("""DECLARE @value nvarchar(256);
EXECUTE master.dbo.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',
N'TcpPort',
@value OUTPUT,
N'no_output';
SELECT @value AS TCP_Port WHERE @value = '1433';""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("2.11:1\n")
else:
    f.write("2.11:0\n")

#2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
#Path change might be required in order to get the correct
cursor.execute("""DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
@rootkey = N'HKEY_LOCAL_MACHINE',
@key = N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib',
@value_name = N'HideInstance',
@value = @getValue OUTPUT;
SELECT @getValue;""")

try:
    row = cursor.fetchone()
    print(row[0])

    if row[0] == 1:
        f.write("2.12:1\n")
    else:
        f.write("2.12:0\n")

except pyodbc.ProgrammingError:
    f.write("2.12:0\n")

#2.13 Ensure 'sa' Login Account is set to 'Disabled' (Scored)
cursor.execute("""SELECT name, is_disabled
FROM sys.server_principals
WHERE sid = 0x01;""")
row = cursor.fetchone()

if row[1] == 0:
    f.write("2.13:0\n")
else:
    f.write("2.13:1\n")

#2.14 Ensure 'sa' Login Account has been renamed (Scored)
cursor.execute("""SELECT name
FROM sys.server_principals
WHERE sid = 0x01;""")
row = cursor.fetchone()

if row[0] == "sa":
    f.write("2.14:0\n")
else:
    f.write("2.14:1\n")

#2.15 Ensure 'xp_cmdshell' Server Configuration Option is set to '0' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'xp_cmdshell';""")
row = cursor.fetchone()

if row[1] == 0 and row[2] == 0:
    f.write("2.15:1\n")
else:
    f.write("2.15:0\n")

#2.16 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Scored)
cursor.execute("""SELECT name, containment, containment_desc, is_auto_close_on
FROM sys.databases
WHERE containment = 0 and is_auto_close_on = 1;""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("2.16:1\n")
else:
    f.write("2.16:0\n")

#2.17 Ensure no login exists with the name 'sa' (Scored)
cursor.execute("""SELECT principal_id, name
FROM sys.server_principals
WHERE name = 'sa';""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("2.17:1\n")
else:
    f.write("2.17:0\n")

##################################### Authentication and Authorization #################################################

#3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored)
cursor.execute("SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') as int) as [login_mode];")
row = cursor.fetchone()

if row[0] == 1:
    f.write("3.1:1\n")
else:
    f.write("3.1:0\n")

#3.2 Ensure CONNECT permissions on the 'guest user' is Revoked within all SQL Server databases excluding the master, msdb and tempdb (Scored)
i = 0
while i < len(dbNames):

    if dbNames[i] == "master" or dbNames[i] == "tempdb" or dbNames[i] == "msdb":
        i += 1
        continue

    cursor.execute("USE "+dbNames[i])
    cursor.execute("""SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User,
    [permission_name], [state_desc]
    FROM sys.database_permissions
    WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
    AND [state_desc] LIKE 'GRANT%'
    AND [permission_name] = 'CONNECT'
    AND DB_NAME() NOT IN ('master','tempdb','msdb');""")

    row = cursor.fetchone()
    if cursor.rowcount != 0:
        f.write("3.2:0\n")
        break
    else:
        if i == len(dbNames)-1:
            f.write("3.2:1\n")

    i += 1

#3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)
i = 0
while i < len(dbNames):

    cursor.execute("USE "+dbNames[i])
    cursor.execute("""EXEC sp_change_users_login @Action='Report';""")

    row = cursor.fetchone()
    if cursor.rowcount != 0:
        f.write("3.3:0\n")
        break
    else:
        if i == len(dbNames)-1:
            f.write("3.3:1\n")

    i += 1

#3.4 Ensure SQL Authentication is not used in contained databases (Scored)
cursor.execute("USE master")
cursor.execute("""SELECT name AS DBUser
FROM sys.database_principals
WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
AND type IN ('U','S','G')
AND authentication_type = 2;""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("3.4:1\n")
else:
    f.write("3.4:0\n")

#3.5 Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (Not Scored)

#3.6 Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (Not Scored)

#3.7 Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (Not Scored)

#3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored)
cursor.execute("""SELECT *
FROM master.sys.server_permissions
WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE
'GRANT%')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and
class_desc = 'SERVER')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 2)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 3)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 4)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 5);""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("3.8:1\n")
else:
    f.write("3.8:0\n")

#3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored)
cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.principal_id = pe.grantee_principal_id
WHERE pr.name like 'BUILTIN%';""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("3.9:1\n")
else:
    f.write("3.9:0\n")

#3.10 Ensure Windows local groups are not SQL Logins (Scored)
cursor.execute("USE [master]")
cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.[principal_id] = pe.[grantee_principal_id]
WHERE pr.[type_desc] = 'WINDOWS_GROUP'
AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("3.10:1\n")
else:
    f.write("3.10:0\n")

#3.11 Ensure the public role in the msdb database is not granted acces to SQL Agent proxies (Scored)
cursor.execute("USE [msdb]")
cursor.execute("""SELECT sp.name AS proxyname
FROM dbo.sysproxylogin spl
JOIN sys.database_principals dp
ON dp.sid = spl.sid
JOIN sysproxies sp
ON sp.proxy_id = spl.proxy_id
WHERE principal_id = USER_ID('public');""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("3.11:1\n")
else:
    f.write("3.11:0\n")

############################################# Password Policies ########################################################

#4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Not Scored)

#4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)
cursor.execute("USE master")
cursor.execute("""SELECT l.[name], 'sysadmin membership' AS 'Access_Method'
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
AND l.is_expiration_checked <> 1
UNION ALL
SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
FROM sys.sql_logins AS l
JOIN sys.server_permissions AS p
ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL' AND p.state IN ('G', 'W')
AND l.is_expiration_checked <> 1;""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("4.2:1\n")
else:
    f.write("4.2:0\n")

#4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored)
cursor.execute("""SELECT name, is_disabled
FROM sys.sql_logins
WHERE is_policy_checked = 0;""")
row = cursor.fetchone()

if cursor.rowcount == 0:
    f.write("4.3:1\n")
else:
    f.write("4.3:0\n")

############################################ Auditing and Logging ######################################################

#5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored)
cursor.execute("USE master")
sql = """
DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
@NumErrorLogs OUTPUT;
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
"""
cursor.execute(sql)

try:
    row = cursor.fetchone()

    if row[0] >= 12:
        f.write("5.1:1\n")
    else:
        f.write("5.1:0\n")

except pyodbc.ProgrammingError:
    f.write("5.1:0\n")

#5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Scored)
cursor.execute("""SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'default trace enabled';""")
row = cursor.fetchone()

if row[1] == 1 and row[2] == 1:
    f.write("5.2:1\n")
else:
    f.write("5.2:0\n")

#5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored)
cursor.execute("""EXEC xp_loginconfig 'audit level';""")
row = cursor.fetchone()

if row[1] == "failure":
    f.write("5.3:1\n")
else:
    f.write("5.3:0\n")

#5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored)
cursor.execute("""SELECT
S.name AS 'Audit Name'
, CASE S.is_state_enabled
WHEN 1 THEN 'Y'
WHEN 0 THEN 'N' END AS 'Audit Enabled'
, S.type_desc AS 'Write Location'
, SA.name AS 'Audit Specification Name'
, CASE SA.is_state_enabled
WHEN 1 THEN 'Y'
WHEN 0 THEN 'N' END AS 'Audit Specification Enabled'
, SAD.audit_action_name
, SAD.audited_result
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA
ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S
ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');""")
row = cursor.fetchone()

count = 0;
while row:

    if row[5] == "AUDIT_CHANGE_GROUP" or row[5] == "FAILED_LOGIN_GROUP" or row[5] == "SUCCESSFUL_LOGIN_GROUP":
        if row[1] == "Y" and row[4] == "Y" and row[6] == "SUCCESS AND FAILURE":
            count += 1

    row = cursor.fetchone()

if count == 3:
    f.write("5.4:1\n")
else:
    f.write("5.4:0\n")

########################################### Application Development ####################################################

#6.1 Ensure Database and Application User Input is Sanitized (Not Scored)

#6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored)
cursor.execute("""SELECT name,
permission_set_desc
FROM sys.assemblies
WHERE is_user_defined = 1;""")
row = cursor.fetchall()

if cursor.rowcount == 0:
    f.write("6.2:1\n")
else:
    x = True
    i = 0

    while i <= len(row):

        if row[0][1] == "SAFE_ACCESS":
            i += 1
            continue
        else:
            x = False
            break

    if x == True:
        f.write("6.2:1\n")
    else:
        f.write("6.2:0\n")

################################################# Encryption ###########################################################

#7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
i = 0
while i < len(userdbNames):

    cursor.execute("USE "+userdbNames[i])
    cursor.execute("""SELECT db_name() AS Database_Name, name AS Key_Name
    FROM sys.symmetric_keys
    WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
    AND db_id() > 4;""")

    row = cursor.fetchone()
    if cursor.rowcount != 0:
        f.write("7.1:0\n")
        break
    else:
        if i == len(userdbNames) - 1:
            f.write("7.1:1\n")

    i += 1

#7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Scored)
i = 0
while i < len(userdbNames):

    cursor.execute("USE "+userdbNames[i])
    cursor.execute("""SELECT db_name() AS Database_Name, name AS Key_Name
    FROM sys.asymmetric_keys
    WHERE key_length < 2048
    AND db_id() > 4;""")

    row = cursor.fetchone()
    if cursor.rowcount != 0:
        f.write("7.2:0\n")
        break
    else:
        if i == len(userdbNames) - 1:
            f.write("7.2:1\n")

    i += 1

#8.1 Ensure 'SQL Server Browser Service' is configured correctly (Not Scored)

cnxn.close()