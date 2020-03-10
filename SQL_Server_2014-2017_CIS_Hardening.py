#!/usr/local/bin/python
# coding: latin-1

#Coded by Qais Temeiza

import pyodbc

server = 'xx.xx.xx.xx,1433'
database = 'master'
username = 'xxxx'
password = 'xxxx'

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

#Open file in order to start writing the results in it
f = open("remediation_results.txt", "w")

####################################### Installation, Updates and Patches ##############################################

#1.1 Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)

#1.2 Ensure Single-Function Member Servers are Used (Not Scored)


########################################### Surface Area Reduction #####################################################

#2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")
	cursor.execute("COMMIT RECONFIGURE;")
	cursor.execute("EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0': Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.1 " + str(e)+"\n")

#2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'clr enabled', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0': Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.2 " + str(e)+"\n")

#2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'cross db ownership chaining', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.3 " + str(e)+"\n")

#2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")
	cursor.execute("COMMIT RECONFIGURE;")
	cursor.execute("EXECUTE sp_configure 'Database Mail XPs', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.4 " + str(e)+"\n")

#2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'Ole Automation Procedures', 0;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.5 " + str(e)+"\n")

#2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'remote access', 0;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.6 " + str(e)+"\n")

#2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'remote admin connections', 0;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	f.write("2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.7 " + str(e)+"\n")

#2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'scan for startup procs', 0;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.8 " + str(e)+"\n")

#2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored)
try:
	cnxn.autocommit = True
	i = 0
	while i < len(dbNames):
		if dbNames[i] == "tempdb" or dbNames[i] == "msdb" or dbNames[i] == "model":
			i += 1
			continue
		else:
			cursor.execute("ALTER DATABASE " + dbNames[i] + " SET TRUSTWORTHY OFF;")
		i += 1
	f.write("2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("2.9 " + str(e)+"\n")

#2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Not Scored)

#2.11 Ensure SQL Server is configured to use non-standard ports (Not Scored)

#2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
#Path change might be required, also permissions should be given to edit registry
try:
	cursor.execute("""EXEC master.sys.xp_instance_regwrite
	@rootkey = N'HKEY_LOCAL_MACHINE',
	@key = N'SOFTWARE\Microsoft\Microsoft SQL
	Server\MSSQLServer\SuperSocketNetLib',
	@value_name = N'HideInstance',
	@type = N'REG_DWORD',
	@value = 1;""")
	f.write("2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.12 " + str(e) +"\n")

#2.13 Ensure 'sa' Login Account is set to 'Disabled' (Scored)
try:
	cursor.execute("USE master")
	cursor.execute("""DECLARE @tsql nvarchar(max)
	SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'
	EXEC (@tsql)""")
	f.write("2.13 Ensure 'sa' Login Account is set to 'Disabled' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.13 " + str(e)+"\n")

#2.14 Ensure 'sa' Login Account has been renamed (Scored)
try:
	cursor.execute("""SELECT name
	FROM sys.server_principals
	WHERE sid = 0x01;""")
	row = cursor.fetchone()

	if row[0] == "sa":
		newUser = raw_input("Please enter the new 'sa' name (this name will get used for the control 2.17 as well):")
		cursor.execute("ALTER LOGIN sa WITH NAME =" + str(newUser) + " ;")
		f.write("2.14 Ensure 'sa' Login Account has been renamed (Scored): Remediated!\n")
	else:
		f.write("2.14 Ensure 'sa' Login Account has been renamed (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.14 " + str(e)+"\n")

#2.15 Ensure 'xp_cmdshell' Server Configuration Option is set to '0' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'xp_cmdshell', 0;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("2.15 Ensure 'xp_cmdshell' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.15 " + str(e)+"\n")

#2.16 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Scored)
try:
	cnxn.autocommit = True
	i = 0
	while i < len(dbNames):

		if dbNames[i] == "master" or dbNames[i] == "tempdb":
			i += 1
			continue
		else:
			cursor.execute("ALTER DATABASE " + dbNames[i] + " SET AUTO_CLOSE OFF;;")
		i += 1
	f.write("2.16 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("2.16 " + str(e)+"\n")

#2.17 Ensure no login exists with the name 'sa' (Scored)
try:
	cursor.execute("""SELECT principal_id, name
	FROM sys.server_principals
	WHERE name = 'sa';""")
	row = cursor.fetchone()

	if cursor.rowcount == 0:
		f.write("2.17 Ensure no login exists with the name 'sa' (Scored): Remediated!\n")
	else:
		cursor.execute("USE [master]")
		cursor.execute("ALTER LOGIN [sa] WITH NAME = " + newUser + " ;")
		#-- If the login owns no database objects, then drop it
		#-- Do NOT drop the login if it is principal_id = 1	
		cursor.execute("DROP LOGIN sa")	
		f.write("2.17 Ensure no login exists with the name 'sa' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("2.17 " + str(e)+"\n")

##################################### Authentication and Authorization #################################################

#3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored)
#Path change might be required, also permissions should be given to edit registry
try:
	cursor.execute("USE [master]")
	cursor.execute("""EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
	N'Software\Microsoft\MSSQLServer\MSSQLServer', 
	N'LoginMode', REG_DWORD, 1""")	
	f.write("3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("3.1 " + str(e)+"\n")

#3.2 Ensure CONNECT permissions on the 'guest user' is Revoked within all SQL Server databases excluding the master, msdb and tempdb (Scored)
try:	
	cnxn.autocommit = True
	i = 0
	while i < len(dbNames):
		if dbNames[i] == "master" or dbNames[i] == "tempdb" or dbNames[i] == "msdb":
			i += 1
			continue
		cursor.execute("USE "+dbNames[i])
		cursor.execute("REVOKE CONNECT FROM guest;")
		i += 1
	f.write("3.2 Ensure CONNECT permissions on the 'guest user' is Revoked within all SQL Server databases excluding the master, msdb and tempdb (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.2 " + str(e)+"\n")

#3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored) ##### NEEDS QA ! #######
try:
	cnxn.autocommit = True
	i = 0
	while i < len(dbNames):
		cursor.execute("USE "+dbNames[i])
		cursor.execute("EXEC sp_change_users_login @Action='Report';")
		row = cursor.fetchall()
		if cursor.rowcount != 0:
			j = 0
			for rows in row:
				cursor.execute("USE "+dbNames[i])
				cursor.execute("DROP USER " + row[j].UserName +" ;")
				j += 1
		i += 1
	f.write("3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.3 " + str(e)+"\n")

#3.4 Ensure SQL Authentication is not used in contained databases (Scored)
#Have to be manually remediated

#3.5 Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (Not Scored)

#3.6 Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (Not Scored)

#3.7 Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (Not Scored)

#3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("USE master")
	cursor.execute("""SELECT permission_name
	FROM master.sys.server_permissions
	WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%')
	AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER')
	AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2)
	AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3)
	AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4)
	AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("USE [master]")
			cursor.execute("REVOKE " + row[i].permission_name + " FROM public;")
			i += 1
	f.write("3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.8 " + str(e) + "\n")

#3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("USE master")
	cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
	FROM sys.server_principals pr
	JOIN sys.server_permissions pe
	ON pr.principal_id = pe.grantee_principal_id
	WHERE pr.name like 'BUILTIN%';""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("USE [master]")
			cursor.execute("DROP LOGIN [BUILTIN\\"+row[i].name+"]")
			i += 1
	f.write("3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.9 " + str(e) + "\n")

#3.10 Ensure Windows local groups are not SQL Logins (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("USE [master]")
	cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
	FROM sys.server_principals pr
	JOIN sys.server_permissions pe
	ON pr.[principal_id] = pe.[grantee_principal_id]
	WHERE pr.[type_desc] = 'WINDOWS_GROUP'
	AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("USE [master]")
			cursor.execute("DROP LOGIN ["+row[i].name+"]")
			i += 1
	f.write("3.10 Ensure Windows local groups are not SQL Logins (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.10 " + str(e) + "\n")

#3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("USE [msdb]")
	cursor.execute("""SELECT sp.name
	FROM dbo.sysproxylogin spl
	JOIN sys.database_principals dp
	ON dp.sid = spl.sid
	JOIN sysproxies sp
	ON sp.proxy_id = spl.proxy_id
	WHERE principal_id = USER_ID('public');""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("USE [msdb]")
			cursor.execute("EXEC dbo.sp_revoke_login_from_proxy @name = N'public', @proxy_name = N'"+row[i].name+"'")
			i += 1
	f.write("3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("3.11 " + str(e) + "\n")

##################################### Password Policies #################################################

#4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)
try:
	cnxn.autocommit = True
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
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("ALTER LOGIN "+row[i].name+" WITH CHECK_EXPIRATION = ON;")
			i += 1
	f.write("4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("4.2 " + str(e) + "\n")

#4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("""SELECT name, is_disabled
	FROM sys.sql_logins
	WHERE is_policy_checked = 0;""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("ALTER LOGIN "+row[i].name+" WITH CHECK_POLICY = ON;")
			i += 1
	f.write("4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("4.3 " + str(e) + "\n")

##################################### Auditing and Logging #################################################

#5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored)
try:
	cnxn.autocommit = True
	sql = """
	DECLARE @NumErrorLogs int;
	EXEC master.sys.xp_instance_regread
	N'HKEY_LOCAL_MACHINE',
	N'Software\Microsoft\MSSQLServer\MSSQLServer',
	N'NumErrorLogs',
	@NumErrorLogs OUTPUT;
	SELECT ISNULL(@NumErrorLogs, -1);
	"""
	cursor.execute(sql)
	row = cursor.fetchone()
	if row[0] < 12:
		newNoOfLogFiles = raw_input("Please enter the new Number Of Log Files (Must be 12 and above):")
		cursor.execute("""EXEC master.sys.xp_instance_regwrite
		N'HKEY_LOCAL_MACHINE',
		N'Software\Microsoft\MSSQLServer\MSSQLServer',
		N'NumErrorLogs',
		REG_DWORD,"""
		+ newNoOfLogFiles + ";")
	f.write("5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("5.1 " + str(e) + "\n")

#5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Scored)
try:
	cursor.execute("EXECUTE sp_configure 'show advanced options', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'default trace enabled', 1;")	
	cursor.execute("COMMIT RECONFIGURE;")	
	cursor.execute("EXECUTE sp_configure 'show advanced options', 0;")
	cursor.execute("COMMIT RECONFIGURE;")
	f.write("5.2 Ensure 'xp_cmdshell' Server Configuration Option is set to '0' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("5.2 " + str(e)+"\n")

#5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored)
#Path change might be required, also permissions should be given to edit registry
try:
	cursor.execute("""EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
	N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel',
	REG_DWORD, 2""")
	f.write("5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored): Remediated!\n")
except pyodbc.ProgrammingError, e:
	f.write("5.3 " + str(e) +"\n")

#5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("CREATE SERVER AUDIT TrackLogins TO APPLICATION_LOG;")	
	cursor.execute("""CREATE SERVER AUDIT SPECIFICATION TrackAllLogins
	FOR SERVER AUDIT TrackLogins
	ADD (FAILED_LOGIN_GROUP),
	ADD (SUCCESSFUL_LOGIN_GROUP),
	ADD (AUDIT_CHANGE_GROUP)
	WITH (STATE = ON);""")	
	cursor.execute("ALTER SERVER AUDIT TrackLogins WITH (STATE = ON);")	
	f.write("#5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("5.4 " + str(e)+"\n")

########################################### Application Development ####################################################

#6.1 Ensure Database and Application User Input is Sanitized (Not Scored)

#6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored)
try:
	cnxn.autocommit = True
	cursor.execute("""SELECT name,
	permission_set_desc
	FROM sys.assemblies
	WHERE is_user_defined = 1;;""")
	row = cursor.fetchall()
	if cursor.rowcount != 0:
		i = 0
		for rows in row:
			cursor.execute("ALTER ASSEMBLY "+row[i].name+" WITH PERMISSION_SET = SAFE;")
			i += 1
	f.write("6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored): Remediated!\n")
	cnxn.autocommit = False
except pyodbc.ProgrammingError, e:
	f.write("6.2 " + str(e) + "\n")

################################################# Encryption ###########################################################

#7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
"""Refer to Microsoft SQL Server Books Online ALTER SYMMETRIC KEY entry:
http://msdn.microsoft.com/en-US/library/ms189440.aspx"""

#7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Scored)
"""Refer to Microsoft SQL Server Books Online ALTER ASYMMETRIC KEY entry:
http://msdn.microsoft.com/en-us/library/ms187311.aspx"""

cnxn.close()
