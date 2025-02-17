# Injectionmap_v2

<a href="https://github.com/pxcs/Injectionmap_v2/"><p align="center">
<img src="/licenses/injectionmap.png">
</p></a>

## Introducing `Injectionmap_v2`

**Injectionmap_v2** is an advanced open-source penetration testing tool that `automates` the detection and exploitation of various types of vulnerabilities in web applications. Building on the capabilities from `SQLMap Project`, Injectionmap_v2 expands its scope to include not only SQL injection but also Blind SQL, NoSQL, Command, LDAP, Directory Traversal, and other Injection Attack techniques. 

# `Python3` and `C`/ `Master` Based

## Features

> - Comprehensive Injection Support: Detects and exploits SQL, Blind SQL, NoSQL, Command, LDAP, Directory Traversal, and other injection vulnerabilities.

> - Wide DBMS Support: Compatible with MySQL, Oracle, PostgreSQL, Microsoft SQL Server, SQLite, MongoDB, and many more.

> - Automated Testing: Automates the process of finding and exploiting injection vulnerabilities.

> - Advanced Techniques: Uses a variety of techniques including boolean-based blind, time-based blind, error-based, UNION query-based, stacked queries, and more.

> - Payloads and Tampering: Includes numerous payloads and tamper scripts to bypass security mechanisms.

> - Database Fingerprinting: Identifies the specific version and features of the targeted DBMS.

> - Data Extraction: Extracts data such as database schema, tables, columns, and sensitive data.

> - Command Execution: Executes arbitrary commands on the database server if privileges allow.

> - Integration: Can be integrated with other tools and scripts for enhanced security testing.

# Installation

Clone the repository:

```shell
git clone https://github.com/byt3n33dl3/Injectionmap_v2.git
cd Injectionmap_v2
```

Install the required dependencies:

```python
pip install -r requirements.txt
```

## Usage

`Injectionmap_v2` is designed to be easy to use with a command line interface, below are some example commands:

**To perform a basic SQL injection test:**

```python
python3 injectionmap -u "http://example.com/vulnerable.php?id=1"
```

To get a list of **basic options** and switches use:

```python
python3 injectionmap -h
python3 injectionmap -hh
```

To get a list of **all options** and switches use:

```shell
python3 Injectionmap_v2 -hh
```

You can find a sample run [here!](https://asciinema.org/a/46601).

**Another** injections attack modules:

> - Blind SQL Injection

> - NoSQL Injection

> - GQL Injection

> - Command Injection

> - LDAP Injection

> - Directory Traversal

# Contribution

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes you would like to make.
License. This project is licensed under the Injectionmap_v2 General Public License. See the LICENSE file for details.
Contact

# Code contributors of Injectionmap_v2:

[![](https://github.com/byt3n33dl3.png?size=50)](https://github.com/byt3n33dl3)
[![](https://avatars.githubusercontent.com/u/675322?s=50&v=4)](https://github.com/bdamele)
[![](https://github.com/zblurx.png?size=50)](https://github.com/zblurx)
[![](https://github.com/guinslym.png?size=50)](https://github.com/guinslym)
[![](https://avatars.githubusercontent.com/u/50994705?s=50&v=4)](https://github.com/projectdiscovery)

# Thanks to

>- SQLMapproject
- GangstaCrew
- The Designer

## For more `informations`
Visit our GitHub `Organization` , or contact us at `byt3n33dl3@proton.me`
