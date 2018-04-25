# DNS-Service-Domain-Checker
The purpose of this script is to query a couple of DNS security services to determine whether or not any or all services are blocking a given domain.

This script will query the following DNS security services:
- Quad9
- Cisco Umbrella (requires an API key)
- Norton ConnectSafe

In order for this script to work, please generate a new API key for Investigate and place it inside the (') qutations next to [token = '']. This script will then ask if you have a file of domains you would like checked, or if you would like to query for one specific domain.

Additionally, this domain will return the status of DNSSEC for the given domain leveraging Quad9.
