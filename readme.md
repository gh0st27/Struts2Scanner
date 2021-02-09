# StrutsExploiter
	
	cve-2020-17530	=> Forced OGNL Evalution : 2.0.0 to 2.5.25
	cve-2019-0230  => Double OGNL Evalution : 2.0.0 to 2.5.20
	cve-2018-11776 => Namespace Redirect OGNL Injection (Default configuration is not vulnerable, but if misconfigured): 2.3.35 to 2.5.17 
	cve-2017-5638 => Jakarta Multipart parsel OGNL Injection: 2.3.5 to 2.3.31 & 2.5 to 2.5.20
	cve-2017-9791 => struts 1 plugin OGNL injeciton: 2.3.x with struts 1 plugin & struts 1 action
	Future Release :cve-2017-9805 => Rest Plugin Xstream RCE : 2.5 to 2.5.12
	Future Release :cve-2013-2251 => Prefix parameter OGNL Injection : 2.0.0 to 2.3.15 (action & redirect & redirectaction is not properly sanitize)


Not Inlcuded:
cve-2019-0233 => DOS

Feature Completed:
 check if endpoint is vulnerable or not
 proxy support
 cookie support
 vulnerable parameter - check Query String & POST Body

Working on:
 Exploit function
 backward compatibility to python
 

Setup

8080/str:

cve-2017-5638
cve-2017-9791
cve-2013-2251
cve-2019-0234

docker: 8088

cve-2018-11776

docker: 8090

cve-2020-17530
