# cons.md

[1] LLM may confidently classify devices incorrectly when fed with ambigious context, such as 'host-02', which could be classified as 'server' or 'workstation' and neither are certain

[2] Isolated system lacks access to real world reachable IPs, DNS servers, DHCP mappings.

[3] System assumes single FQDN per host, while servers may ahve different FQDNs for different network interfaces (management or backup networks?)

[4] Subnet CIDR is always defaulting to /24 format

[5] MAC Validation is only normalizing and not extracting Vendor (First 3 octets)

[6] System is not tracking whether IPs are Static or DHCP (How would we clarify such setting?)
