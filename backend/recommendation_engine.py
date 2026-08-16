def get_recommendations(attack_label):
    """
    Returns detailed security recommendations and steps based on the type of attack detected.
    """
    rec_dict = {
        'BENIGN': {
            'severity': 'LOW',
            'summary': 'No threat detected. Normal network flow.',
            'actions': [
                'No action required.',
                'Continue monitoring normal traffic.',
                'Ensure standard firewalls and access controls remain active.'
            ]
        },
        'DoS Hulk': {
            'severity': 'HIGH',
            'summary': 'HTTP Flooding DoS attack attempting to exhaust server resources.',
            'actions': [
                'Implement HTTP rate limiting at the reverse proxy (e.g., Nginx, Apache) or Web Application Firewall (WAF).',
                'Deploy dynamic firewall rules (e.g., using iptables/ipset) to block or limit requests from the source IP.',
                'Enable connection limit modules to restrict maximum concurrent connections per IP address.',
                'Enable TCP SYN cookies on the target server to mitigate connection table state exhaustion.'
            ]
        },
        'DDoS': {
            'severity': 'CRITICAL',
            'summary': 'Distributed Denial of Service attack aiming to saturate network bandwidth.',
            'actions': [
                'Engage upstream ISP or cloud-based scrubbing services (e.g., Cloudflare, AWS Shield) to filter volumetric traffic.',
                'Deploy Access Control Lists (ACLs) to drop incoming traffic from the attacker IP subnet.',
                'Configure edge firewalls to drop spoofed IP packets and filter unauthenticated traffic.',
                'Configure rate limits for DNS, ICMP, and UDP traffic to minimize resource amplification.'
            ]
        },
        'PortScan': {
            'severity': 'MEDIUM',
            'summary': 'Active host reconnaissance identifying open ports and active services.',
            'actions': [
                'Configure Fail2Ban or an Intrusion Prevention System (IPS) to temporarily block IPs scanning multiple ports.',
                'Disable unused services and close unnecessary open ports in the network security group.',
                'Configure the firewall to silently drop packets on closed ports (stealth mode) instead of returning TCP RST packets.',
                'Inspect system logs to verify if the scanning IP attempted connections to high-value ports.'
            ]
        },
        'FTP-Patator': {
            'severity': 'HIGH',
            'summary': 'Brute-force password guessing attack targeting FTP services (Port 21).',
            'actions': [
                'Temporarily block the source IP using fail2ban or a local firewall rule.',
                'Enforce account lockout policies after a small number of failed login attempts.',
                'Disable anonymous FTP logins and enforce secure FTP protocols (SFTP / FTPS) with encryption.',
                'Review FTP server access logs to check if any attempts succeeded.'
            ]
        },
        'SSH-Patator': {
            'severity': 'HIGH',
            'summary': 'Brute-force password guessing attack targeting SSH services (Port 22).',
            'actions': [
                'Block the source IP using fail2ban, host-based firewalls, or TCP wrappers.',
                'Disable password-based authentication for SSH, enforcing public key authentication instead.',
                'Change the default SSH port (22) to a non-standard high port to evade automatic scanners.',
                'Restrict SSH access using IP whitelisting or enforce connection through a VPN / Bastion Host.'
            ]
        },
        'Web Attack': {
            'severity': 'HIGH',
            'summary': 'Web application exploit attempt (SQL Injection, XSS, or Command Injection).',
            'actions': [
                'Deploy or update rules on a Web Application Firewall (WAF) to filter common attack patterns (SQLi, XSS).',
                'Ensure all database queries use parameterized APIs (prepared statements) to block SQL Injection payloads.',
                'Apply output encoding and Content Security Policy (CSP) headers to neutralize Cross-Site Scripting (XSS).',
                'Sanitize and validate all user inputs on the backend prior to processing.',
                'Check web server logs for HTTP status code responses (e.g., 200 vs 500/403) to see if the attack was successful.'
            ]
        }
    }
    
    return rec_dict.get(attack_label, {
        'severity': 'MEDIUM',
        'summary': f'Suspicious network activity classified as {attack_label}.',
        'actions': [
            'Monitor the source IP address for further anomalous traffic.',
            'Audit firewall and security group rules associated with the destination port.',
            'Verify server system logs for signs of unauthorized access.'
        ]
    })
