# SQL Server 2014-2017 CIS Benchmark
Python scripts to check how compliant is the 2014-2017 Microsoft SQL Server:

-The auditing script checks for all "Scored" controls

-The remediation scripts remediates all of the "Scored" controls


# Notes regarding the remediation/hardening script:

-Kerberos should be configured in order to use Windows Authentication

-For the controls that require registry modification, path change might be required, also permissions should be given to edit registry
