# Ansible Role: NKOSI

Installs and configures NKOSI Linux security agent.

## Requirements

- Ansible 2.9+
- Debian/Ubuntu target hosts
- Root access on targets

## Role Variables

```yaml
nkosi_version: "0.1.0"
nkosi_agent_name: "{{ inventory_hostname }}"
nkosi_firewall_enabled: true
nkosi_ssh_block_threshold: 10
nkosi_notify_enabled: false
nkosi_notify_email: ""
nkosi_notify_webhook: ""
```

## Example Playbook

```yaml
- hosts: servers
  roles:
    - role: nkosi
      vars:
        nkosi_version: "0.1.0"
        nkosi_firewall_enabled: true
        nkosi_notify_enabled: true
        nkosi_notify_email: "admin@example.com"
```

## Multi-host Deployment

```yaml
- hosts: all
  roles:
    - role: nkosi
      vars:
        nkosi_version: "0.1.0"

# Central server
- hosts: central
  roles:
    - role: nkosi
      vars:
        nkosi_version: "0.1.0"
```

## License

MIT
