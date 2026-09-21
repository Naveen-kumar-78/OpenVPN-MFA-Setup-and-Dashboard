# OpenVPN-MFA-Setup-and-Dashboard
OpenVPN setup that integrates TOTP-based MFA, connection auditing hooks, and an HTML/templated dashboard for real-time visibility of users and logs.
To use this VPN just take this code and run the script in your subnet master server thats it done your own vpn is ready to use 
flowchart TD

subgraph group_deployment["Deployment"]
  node_vpn_script["VPN Setup<br/>[vpn.sh]"]
  node_ovpn_script["OpenVPN Setup<br/>[ovpn.sh]"]
  node_client_script["Client Helper<br/>[client.sh]"]
end

subgraph group_vpn_runtime["VPN Runtime"]
  node_openvpn["OpenVPN Service"]
end

subgraph group_security["Security"]
  node_totp_mfa["TOTP MFA"]
end

subgraph group_visibility["Visibility"]
  node_audit_hooks["Audit Hooks"]
  node_dashboard["Live Dashboard"]
end

node_administrator(("Administrator"))
node_vpn_user(("VPN User"))

node_administrator -->|"runs"| node_vpn_script
node_vpn_script -->|"sets up"| node_openvpn
node_ovpn_script -->|"configures"| node_openvpn
node_client_script -->|"connects"| node_openvpn
node_vpn_user -->|"connects"| node_openvpn
node_openvpn -->|"authenticates"| node_totp_mfa
node_openvpn -->|"audits"| node_audit_hooks
node_audit_hooks -->|"feeds logs"| node_dashboard

click node_vpn_script "https://github.com/naveen-kumar-78/openvpn-mfa-setup-and-dashboard/blob/main/vpn.sh"
click node_ovpn_script "https://github.com/naveen-kumar-78/openvpn-mfa-setup-and-dashboard/blob/main/ovpn.sh"
click node_client_script "https://github.com/naveen-kumar-78/openvpn-mfa-setup-and-dashboard/blob/main/client.sh"

classDef toneNeutral fill:#f8fafc,stroke:#334155,stroke-width:1.5px,color:#0f172a
classDef toneBlue fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef toneAmber fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef toneMint fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef toneRose fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef toneIndigo fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81
classDef toneTeal fill:#ccfbf1,stroke:#0f766e,stroke-width:1.5px,color:#134e4a
class node_vpn_script,node_ovpn_script,node_client_script,node_vpn_user toneBlue
class node_openvpn toneAmber
class node_totp_mfa toneMint
class node_audit_hooks,node_dashboard toneRose
class node_administrator toneIndigo
