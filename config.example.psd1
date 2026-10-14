@{
    # Address of the ONT web UI.
    RouterIp     = '192.168.0.1'

    # Web UI credentials. The default login for these ONTs is often
    # 'admin' / 'act@123' (ACT Fibernet) - change it to your own.
    Username     = 'admin'
    Password     = ''

    # Seconds to wait after the reboot before the first "new IP" check.
    InitialDelay = 20

    # Maximum number of seconds to wait for a new public IP.
    Timeout      = 300
}
