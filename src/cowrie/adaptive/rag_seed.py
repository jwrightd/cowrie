# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
from typing import Any

from cowrie.adaptive.rag import EmbeddingClient
from cowrie.adaptive.sidecar import make_store

_SOURCE_NAME = "adaptive-handler-generation-corpus"
_SOURCE_TYPE = "curated-handler-rag"
_SOURCE_VERSION = "2026-06-05"
_SOURCE_URI = "builtin:cowrie.adaptive.rag_seed"


def _doc(
    title: str,
    text: str,
    topic: str,
    *,
    command: str = "",
    argv_pattern: list[str] | None = None,
    source_type: str = "curated",
    priority: str = "medium",
    risk_level: str = "safe",
) -> dict[str, Any]:
    return {
        "text": f"Title: {title}\n{text.strip()}",
        "metadata": {
            "title": title,
            "topic": topic,
            "command": command,
            "argv_pattern": argv_pattern or [],
            "source_type": source_type,
            "priority": priority,
            "risk_level": risk_level,
        },
    }


def _handler_doc(
    title: str,
    command: str,
    argv_pattern: list[str],
    spec: dict[str, Any],
    guidance: str,
) -> dict[str, Any]:
    return _doc(
        title,
        (
            f"Command: {command}\n"
            f"Triggering argv: {json.dumps(argv_pattern)}\n"
            f"Handler guidance: {guidance}\n"
            "Valid declarative JSON handler example:\n"
            f"{json.dumps(spec, sort_keys=True)}"
        ),
        "json_handler_example",
        command=command,
        argv_pattern=argv_pattern,
        source_type="accepted-handler-example",
        priority="high",
    )


_DEFAULT_RAG_DOCUMENTS = [
    _doc(
        "Declarative handler contract v1",
        """
        Adaptive handlers must be declarative JSON, not Python code. Required
        fields are command, argv_match, response, exit_status, fs_effects, and
        state_effects. The command field is the executable name only. The
        argv_match field describes arguments only and must not include the
        command name. response must be an object with stdout and stderr strings.
        fs_effects may only describe fake filesystem writes under /tmp,
        /var/tmp, /home, or /root. state_effects is session-local scalar state.
        """,
        "handler_schema",
        priority="critical",
    ),
    _doc(
        "Validator rejection patterns",
        """
        Reject or repair generated specs that include the command name in
        argv_match, use argv_match as a string instead of an object, return
        response as a list or object with non-string fields, use nested
        state_effects, write outside fake writable paths, request imports,
        subprocesses, network calls, or host filesystem writes.
        """,
        "validator_guidance",
        priority="critical",
    ),
    _doc(
        "Safe argv matching",
        """
        For bare commands, prefer argv_match {"mode":"exact","patterns":[]}.
        For one concrete missed form, prefer exact or prefix matching against
        the triggering argv only. Examples: command ss with argv [] should not
        match ss -tulpn. command ss with argv ["-tulpn"] can use exact
        patterns ["-tulpn"]. Use broader matchers only when the response is
        valid for all matched variants.
        """,
        "validator_guidance",
        priority="critical",
    ),
    _doc(
        "Cowrie fake environment baseline",
        """
        Generate outputs as if the attacker is in a Debian or Ubuntu-like
        root shell inside a medium-interaction honeypot. Keep outputs
        internally consistent: hostname unitTest or svr04, user root, cwd
        usually /root, shell prompt root@host:~#. Avoid leaking the real host.
        Prefer small realistic outputs over exhaustive host inventories.
        """,
        "cowrie_environment",
        priority="high",
    ),
    _doc(
        "Cowrie filesystem consistency",
        """
        Cowrie uses a fake filesystem and simple text command outputs for many
        commands. Handler responses should align with fake files such as
        /etc/passwd, /etc/hostname, /etc/os-release, /root, /home, /tmp, and
        /var/log. If a handler creates files, create only fake files using
        fs_effects and avoid modifying sensitive real paths.
        """,
        "cowrie_environment",
        priority="high",
    ),
    _doc(
        "Minimal host profile",
        """
        A believable minimal Linux honeypot can have lo and eth0, root user,
        ssh or sshd service, a small process list, no Docker daemon, no
        Kubernetes tools, limited journal history, and normal /tmp write
        behavior. This profile gives attackers useful engagement without
        claiming rich services that later commands cannot support.
        """,
        "cowrie_environment",
        priority="high",
    ),
    _doc(
        "No systemd profile",
        """
        Many containers and minimal environments do not have systemd as PID 1.
        For systemctl commands in that profile, stderr can be
        "System has not been booted with systemd as init system (PID 1). Can't
        operate." followed by "Failed to connect to bus: Host is down" or
        "Failed to connect to bus: No such file or directory". Use exit status
        1 for that failure.
        """,
        "cowrie_environment",
        command="systemctl",
        priority="high",
    ),
    _doc(
        "Systemd host profile",
        """
        If the honeypot chooses a systemd-capable profile, systemctl status ssh
        should return a compact unit status with Loaded, Active, Main PID,
        Tasks, Memory, CGroup, and a few recent journal lines. Keep timestamps,
        hostnames, process names, and service names consistent with journalctl
        outputs.
        """,
        "cowrie_environment",
        command="systemctl",
        priority="high",
    ),
    _doc(
        "ip command behavior",
        """
        ip shows and manipulates routing, network devices, interfaces, and
        tunnels. Common read-only attacker probes include ip addr, ip a,
        ip link, ip route, ip neigh, ip -br addr, and ip -o addr. ip addr
        normally lists lo and network interfaces with link, inet, inet6, scope,
        and lifetime fields. Syntax errors exit non-zero.
        """,
        "command_behavior",
        command="ip",
        priority="high",
    ),
    _doc(
        "ip addr realistic output",
        """
        Example stdout for ip addr:
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
            link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
            inet 127.0.0.1/8 scope host lo
               valid_lft forever preferred_lft forever
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
            link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
            inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
               valid_lft forever preferred_lft forever
        """,
        "output_example",
        command="ip",
        argv_pattern=["addr"],
        priority="high",
    ),
    _doc(
        "ip route realistic output",
        """
        Example stdout for ip route:
        default via 172.17.0.1 dev eth0
        172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.2
        Use this style for route discovery. For minimal honeypots, keep route
        tables short and consistent with the eth0 address chosen in ip addr.
        """,
        "output_example",
        command="ip",
        argv_pattern=["route"],
        priority="high",
    ),
    _doc(
        "ss command behavior",
        """
        ss dumps socket statistics. With no options, it shows open
        non-listening sockets such as established TCP, UDP, or Unix sockets.
        ss -l shows listening sockets. ss -tulpn lists listening TCP and UDP
        sockets with numeric ports and process info. Columns commonly include
        Netid, State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port,
        and Process.
        """,
        "command_behavior",
        command="ss",
        priority="high",
    ),
    _doc(
        "ss bare realistic output",
        """
        For bare ss, a quiet minimal host may show only the header or a small
        set of established sessions. Example stdout:
        Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        u_str ESTAB 0 0 * 27491 * 27492
        tcp ESTAB 0 0 172.17.0.2:ssh 172.17.0.1:53144
        Do not include LISTEN rows unless the argv requests listening sockets.
        """,
        "output_example",
        command="ss",
        argv_pattern=[],
        priority="high",
    ),
    _doc(
        "ss -tulpn realistic output",
        """
        Example stdout for ss -tulpn:
        Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=713,fd=3))
        tcp   LISTEN 0      128             [::]:22           [::]:*     users:(("sshd",pid=713,fd=4))
        udp   UNCONN 0      0        127.0.0.53:53        0.0.0.0:*     users:(("systemd-resolve",pid=408,fd=12))
        """,
        "output_example",
        command="ss",
        argv_pattern=["-tulpn"],
        priority="high",
    ),
    _doc(
        "netstat command behavior",
        """
        netstat is older than ss but attackers still use netstat -antp,
        netstat -tulpn, netstat -rn, and netstat -ano. If netstat is not
        installed, return "netstat: command not found". If supported, use
        Proto, Recv-Q, Send-Q, Local Address, Foreign Address, State, and
        PID/Program name columns.
        """,
        "command_behavior",
        command="netstat",
        priority="medium",
    ),
    _doc(
        "ifconfig command behavior",
        """
        ifconfig displays interface configuration. Minimal output usually
        includes eth0 and lo, with flags, mtu, inet, netmask, broadcast,
        inet6, ether, RX/TX packets, errors, dropped, and bytes. Keep MAC and
        IP values aligned with ip addr chunks.
        """,
        "command_behavior",
        command="ifconfig",
        priority="medium",
    ),
    _doc(
        "route command behavior",
        """
        route -n shows kernel routing table with Destination, Gateway,
        Genmask, Flags, Metric, Ref, Use, and Iface. For a container-like
        profile, include default gateway via eth0 and the local bridge subnet.
        """,
        "command_behavior",
        command="route",
        priority="medium",
    ),
    _doc(
        "systemctl command behavior",
        """
        Common attacker probes are systemctl status ssh, systemctl status sshd,
        systemctl list-units --type=service, systemctl is-active ssh, and
        systemctl enable/start commands. For read-only probes, generate compact
        believable systemd output. For state-changing actions, prefer
        permission, bus, or unit-not-found failures unless the fake environment
        explicitly supports the state transition.
        """,
        "command_behavior",
        command="systemctl",
        priority="high",
    ),
    _doc(
        "systemctl status ssh realistic output",
        """
        Example stdout for systemctl status ssh:
        * ssh.service - OpenBSD Secure Shell server
             Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
             Active: active (running) since Fri 2026-06-05 13:12:44 UTC; 2h 18min ago
           Main PID: 713 (sshd)
              Tasks: 1 (limit: 2318)
             Memory: 5.8M
             CGroup: /system.slice/ssh.service
                     `-713 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
        Use exit_status 0 for the systemd host profile.
        """,
        "output_example",
        command="systemctl",
        argv_pattern=["status", "ssh"],
        priority="high",
    ),
    _doc(
        "service command behavior",
        """
        service ssh status is a SysV-style alternative to systemctl. It can
        show "* sshd is running" or a short OpenBSD Secure Shell server status.
        If the service name is unknown, stderr commonly says unrecognized
        service and exits non-zero.
        """,
        "command_behavior",
        command="service",
        priority="medium",
    ),
    _doc(
        "journalctl command behavior",
        """
        journalctl prints systemd journal entries. Common probes include
        journalctl -u ssh --no-pager -n 50, journalctl -xe, journalctl -n 20,
        and journalctl --since today. If no journal is available, return
        "No journal files were found." or "No entries". With service logs,
        use timestamped host/service lines.
        """,
        "command_behavior",
        command="journalctl",
        priority="high",
    ),
    _doc(
        "journalctl ssh realistic output",
        """
        Example stdout for journalctl -u ssh --no-pager -n 50:
        Jun 05 13:12:44 svr04 systemd[1]: Started OpenBSD Secure Shell server.
        Jun 05 13:12:44 svr04 sshd[713]: Server listening on 0.0.0.0 port 22.
        Jun 05 13:12:44 svr04 sshd[713]: Server listening on :: port 22.
        Jun 05 15:21:18 svr04 sshd[1482]: Accepted password for root from 172.17.0.1 port 53144 ssh2
        Keep journal lines consistent with systemctl status and ss output.
        """,
        "output_example",
        command="journalctl",
        argv_pattern=["-u", "ssh"],
        priority="high",
    ),
    _doc(
        "docker command behavior",
        """
        Common attacker probes are docker ps, docker ps -a, docker images,
        docker version, docker info, and docker.sock permission checks. If
        Docker is installed and daemon reachable, docker ps uses columns
        CONTAINER ID, IMAGE, COMMAND, CREATED, STATUS, PORTS, NAMES. If the
        daemon is unavailable, return the standard cannot-connect message.
        """,
        "command_behavior",
        command="docker",
        priority="high",
    ),
    _doc(
        "docker ps realistic outputs",
        """
        Empty daemon stdout:
        CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
        Daemon unavailable stderr:
        Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
        Permission denied stderr:
        Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
        """,
        "output_example",
        command="docker",
        argv_pattern=["ps"],
        priority="high",
    ),
    _doc(
        "kubectl command behavior",
        """
        Attackers check for Kubernetes with kubectl get pods, kubectl get
        nodes, kubectl config view, and kubectl auth can-i. On a non-cluster
        honeypot, kubectl may be missing. If present without config, stderr can
        say the connection to localhost:8080 was refused or no configuration
        has been provided.
        """,
        "command_behavior",
        command="kubectl",
        priority="medium",
    ),
    _doc(
        "crictl command behavior",
        """
        crictl probes container runtimes. Common forms are crictl ps, crictl
        images, and crictl info. On hosts without a configured runtime,
        stderr commonly reports connection failure to containerd, CRI-O, or
        dockershim sockets.
        """,
        "command_behavior",
        command="crictl",
        priority="medium",
    ),
    _doc(
        "uname behavior",
        """
        uname, uname -a, uname -m, and uname -r are system discovery commands.
        uname -a should return a single line with kernel name, hostname,
        kernel release, build timestamp, architecture, and GNU/Linux. Keep the
        hostname consistent with other outputs.
        """,
        "command_behavior",
        command="uname",
        priority="medium",
    ),
    _doc(
        "os-release behavior",
        """
        cat /etc/os-release and lsb_release -a reveal distribution details.
        Good fake profile: Ubuntu 20.04 or Debian 11/12. Keep PRETTY_NAME,
        VERSION_ID, ID, and VERSION_CODENAME consistent. Avoid claiming a
        distro whose paths and services contradict later outputs.
        """,
        "command_behavior",
        command="cat",
        argv_pattern=["/etc/os-release"],
        priority="high",
    ),
    _doc(
        "lscpu behavior",
        """
        lscpu prints CPU architecture, CPU op-modes, byte order, CPU count,
        model name, virtualization, cache sizes, and vulnerability fields. For
        a small honeypot, 1 or 2 vCPUs and x86_64 are believable. Keep output
        short unless the attacker explicitly requests verbose hardware detail.
        """,
        "command_behavior",
        command="lscpu",
        priority="medium",
    ),
    _doc(
        "free behavior",
        """
        free -m or free -h shows Mem and Swap rows. Minimal host example:
        total around 512Mi to 2Gi, used modest, buff/cache present, swap 0 or
        1Gi. Columns are total, used, free, shared, buff/cache, available.
        """,
        "command_behavior",
        command="free",
        priority="medium",
    ),
    _doc(
        "df behavior",
        """
        df -h shows filesystem capacity. A believable minimal host has
        overlay or /dev/root mounted on /, tmpfs on /dev, /run, and /dev/shm.
        Use Filesystem, Size, Used, Avail, Use%, Mounted on columns.
        """,
        "command_behavior",
        command="df",
        priority="medium",
    ),
    _doc(
        "mount behavior",
        """
        mount shows mounted filesystems. Container-like profiles include
        overlay on /, proc on /proc, tmpfs on /dev, devpts on /dev/pts, sysfs
        on /sys, cgroup on /sys/fs/cgroup, and shm on /dev/shm.
        """,
        "command_behavior",
        command="mount",
        priority="medium",
    ),
    _doc(
        "ps behavior",
        """
        ps aux and ps -ef show process lists. A small fake host can include
        root PID 1 init or systemd, sshd listener, bash for the current
        session, and the ps command itself. Keep PIDs consistent enough for
        systemctl, journalctl, and ss chunks.
        """,
        "command_behavior",
        command="ps",
        priority="high",
    ),
    _doc(
        "top behavior",
        """
        top -b -n 1 returns task summary, CPU percentages, memory summary, and
        process table. If interactive top is requested without batch flags, a
        simple static snapshot is acceptable for a honeypot handler.
        """,
        "command_behavior",
        command="top",
        priority="medium",
    ),
    _doc(
        "who and w behavior",
        """
        who and w show logged-in users. For root SSH honeypot sessions, include
        root on pts/0 from the attack source IP. w also shows uptime, load
        averages, and WHAT as -bash or sshd session activity.
        """,
        "command_behavior",
        command="w",
        priority="medium",
    ),
    _doc(
        "last behavior",
        """
        last shows login history from wtmp. A plausible honeypot response has
        one or more root pts/0 SSH logins from private or attacker source IPs
        plus a wtmp begins line. Keep timestamps recent and compact.
        """,
        "command_behavior",
        command="last",
        priority="medium",
    ),
    _doc(
        "crontab behavior",
        """
        crontab -l is common persistence discovery. For root with no crontab,
        stderr can be "no crontab for root" with exit status 1. If you choose
        to expose fake persistence bait, keep it benign and internally
        consistent with files under /etc/cron*.
        """,
        "command_behavior",
        command="crontab",
        priority="medium",
    ),
    _doc(
        "find discovery behavior",
        """
        Attackers use find for writable directories, SUID discovery, recently
        modified files, SSH keys, and config files. Safe honeypot responses
        should be bounded and fake. Avoid returning huge filesystem listings.
        For permission-heavy scans, include a few Permission denied lines and
        a small number of plausible paths.
        """,
        "command_behavior",
        command="find",
        priority="medium",
        risk_level="dual_use_safe_summary",
    ),
    _doc(
        "grep discovery behavior",
        """
        grep is used to search configs, histories, process output, and logs.
        Handler output depends strongly on the file operands. If file paths do
        not exist in the fake filesystem, return grep: path: No such file or
        directory. If searching /etc/passwd, emit only fake file matches.
        """,
        "command_behavior",
        command="grep",
        priority="medium",
    ),
    _doc(
        "env and printenv behavior",
        """
        env and printenv reveal environment variables. Return bounded values
        such as SHELL=/bin/bash, USER=root, LOGNAME=root, HOME=/root,
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
        PWD=/root, and TERM=xterm.
        """,
        "command_behavior",
        command="env",
        priority="medium",
    ),
    _doc(
        "history behavior",
        """
        history may be empty, unavailable, or show a small list of fake prior
        commands. Avoid exposing real operator commands. If no history exists,
        return no stdout and exit 0, or a shell-specific message only if
        appropriate.
        """,
        "command_behavior",
        command="history",
        priority="medium",
    ),
    _doc(
        "apt behavior",
        """
        apt, apt-get, dpkg, yum, and apk are used for package discovery and
        installation. For read-only version/list probes, return package tool
        metadata. For install/update operations, prefer permission, lock,
        network, or repository failure messages rather than pretending to
        install real packages.
        """,
        "command_behavior",
        command="apt",
        priority="medium",
    ),
    _doc(
        "download tool behavior",
        """
        wget and curl are often used to retrieve payloads. Cowrie can capture
        downloads separately. Handler specs should not perform real network
        calls. If simulating output, emit realistic progress or error text and
        use fake fs_effects only under allowed paths when the command clearly
        writes a file.
        """,
        "command_behavior",
        command="curl",
        priority="high",
        risk_level="dual_use_safe_summary",
    ),
    _doc(
        "shell interpreter behavior",
        """
        sh, bash, dash, ash, and zsh may be invoked with -c or script paths.
        The adaptive JSON handler should never execute script contents. For
        shell invocations, prefer safe static errors, bounded fake output, or
        session-local state. Do not interpret attacker-provided shell as code.
        """,
        "command_behavior",
        command="sh",
        priority="critical",
        risk_level="dual_use_safe_summary",
    ),
    _doc(
        "Discovery sequence: basic identity",
        """
        Typical attacker flow: id, whoami, uname -a, hostname, pwd,
        cat /etc/os-release. If a miss happens in this context, generate
        output consistent with root access, the same hostname, and the same
        OS profile. This sequence maps to account and system information
        discovery.
        """,
        "attack_sequence",
        priority="high",
    ),
    _doc(
        "Discovery sequence: network",
        """
        Typical attacker flow: ip addr, ifconfig, ip route, route -n,
        ss -tulpn, netstat -antp, cat /etc/resolv.conf. If a miss happens
        here, prioritize network command handlers and keep interfaces, routes,
        DNS, listening ports, and process names consistent.
        """,
        "attack_sequence",
        priority="high",
    ),
    _doc(
        "Discovery sequence: services",
        """
        Typical attacker flow: ps aux, systemctl status ssh, systemctl
        list-units, service --status-all, journalctl -u ssh. If a miss happens
        here, choose either the systemd host profile or the no-systemd profile
        and keep all service-related outputs aligned.
        """,
        "attack_sequence",
        priority="high",
    ),
    _doc(
        "Discovery sequence: container checks",
        """
        Typical attacker flow: docker ps, docker images, kubectl get pods,
        crictl ps, ls /.dockerenv, cat /proc/1/cgroup. A minimal honeypot can
        expose container hints while denying daemon access. Avoid claiming a
        full Kubernetes cluster unless you can support follow-up commands.
        """,
        "attack_sequence",
        priority="high",
    ),
    _doc(
        "Discovery sequence: privilege and persistence",
        """
        Typical attacker flow: sudo -l, find scans, crontab -l, ls -la /etc,
        cat shell history, check writable directories. Keep outputs bounded,
        fake, and safe. This RAG chunk is for deception realism, not for
        providing exploit instructions.
        """,
        "attack_sequence",
        priority="medium",
        risk_level="dual_use_safe_summary",
    ),
    _doc(
        "Safe GTFOBins intent summary",
        """
        GTFOBins-style references are useful only as high-level intent labels:
        shell escape, file read, file write, download, upload, or privilege
        discovery. Do not place exploit recipes in handler prompts. Use intent
        labels to decide whether to return realistic denial, empty results, or
        bounded fake filesystem output.
        """,
        "attack_taxonomy",
        priority="medium",
        risk_level="dual_use_safe_summary",
    ),
    _handler_doc(
        "Accepted handler: bare ss",
        "ss",
        [],
        {
            "command": "ss",
            "argv_match": {"mode": "exact", "patterns": []},
            "response": {
                "stdout": (
                    "Netid State Recv-Q Send-Q Local Address:Port "
                    "Peer Address:Port Process\n"
                    "tcp ESTAB 0 0 172.17.0.2:ssh 172.17.0.1:53144\n"
                ),
                "stderr": "",
            },
            "exit_status": 0,
            "fs_effects": [],
            "state_effects": {},
        },
        "Bare ss must use exact empty argv and must not match ss -tulpn.",
    ),
    _handler_doc(
        "Accepted handler: ss -tulpn",
        "ss",
        ["-tulpn"],
        {
            "command": "ss",
            "argv_match": {"mode": "exact", "patterns": ["-tulpn"]},
            "response": {
                "stdout": (
                    "Netid State  Recv-Q Send-Q Local Address:Port "
                    "Peer Address:Port Process\n"
                    "tcp   LISTEN 0      128          0.0.0.0:22        "
                    "0.0.0.0:*     users:((\"sshd\",pid=713,fd=3))\n"
                ),
                "stderr": "",
            },
            "exit_status": 0,
            "fs_effects": [],
            "state_effects": {},
        },
        "Use argv only, not the command name, and keep output in ss columns.",
    ),
    _handler_doc(
        "Accepted handler: ip route",
        "ip",
        ["route"],
        {
            "command": "ip",
            "argv_match": {"mode": "exact", "patterns": ["route"]},
            "response": {
                "stdout": (
                    "default via 172.17.0.1 dev eth0\n"
                    "172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.2\n"
                ),
                "stderr": "",
            },
            "exit_status": 0,
            "fs_effects": [],
            "state_effects": {"network_profile": "container-eth0"},
        },
        "Make route output consistent with ip addr and fake eth0 profile.",
    ),
    _handler_doc(
        "Accepted handler: systemctl no-systemd failure",
        "systemctl",
        ["status", "ssh"],
        {
            "command": "systemctl",
            "argv_match": {"mode": "exact", "patterns": ["status", "ssh"]},
            "response": {
                "stdout": "",
                "stderr": (
                    "System has not been booted with systemd as init system "
                    "(PID 1). Can't operate.\n"
                    "Failed to connect to bus: Host is down\n"
                ),
            },
            "exit_status": 1,
            "fs_effects": [],
            "state_effects": {"service_profile": "no-systemd"},
        },
        "Use this in a container/minimal profile, not in a systemd host profile.",
    ),
    _handler_doc(
        "Accepted handler: journalctl ssh logs",
        "journalctl",
        ["-u", "ssh", "--no-pager", "-n", "50"],
        {
            "command": "journalctl",
            "argv_match": {
                "mode": "exact",
                "patterns": ["-u", "ssh", "--no-pager", "-n", "50"],
            },
            "response": {
                "stdout": (
                    "Jun 05 13:12:44 svr04 systemd[1]: Started OpenBSD Secure Shell server.\n"
                    "Jun 05 13:12:44 svr04 sshd[713]: Server listening on 0.0.0.0 port 22.\n"
                    "Jun 05 15:21:18 svr04 sshd[1482]: Accepted password for root from 172.17.0.1 port 53144 ssh2\n"
                ),
                "stderr": "",
            },
            "exit_status": 0,
            "fs_effects": [],
            "state_effects": {},
        },
        "Keep logs compact and consistent with ssh service/process outputs.",
    ),
    _handler_doc(
        "Accepted handler: docker ps daemon unavailable",
        "docker",
        ["ps"],
        {
            "command": "docker",
            "argv_match": {"mode": "exact", "patterns": ["ps"]},
            "response": {
                "stdout": "",
                "stderr": (
                    "Cannot connect to the Docker daemon at "
                    "unix:///var/run/docker.sock. Is the docker daemon running?\n"
                ),
            },
            "exit_status": 1,
            "fs_effects": [],
            "state_effects": {"container_runtime": "docker-socket-unavailable"},
        },
        "Useful for container probing without pretending Docker actually works.",
    ),
    _doc(
        "Rejected handler example: command inside argv_match",
        """
        Bad JSON example:
        {"command":"ss","argv_match":{"mode":"exact","patterns":["ss","ss -a"]},...}
        This is wrong because argv_match contains arguments only. For bare ss,
        use {"mode":"exact","patterns":[]}. For ss -a, use
        {"mode":"exact","patterns":["-a"]}.
        """,
        "rejected_handler_example",
        command="ss",
        priority="critical",
    ),
    _doc(
        "Rejected handler example: unsafe effects",
        """
        Bad JSON examples include fs_effects writing /etc/passwd, /var/log
        host files, or arbitrary absolute host paths; response values that are
        objects instead of strings; and state_effects containing nested lists
        or dictionaries. Use fake writable paths only and scalar session state.
        """,
        "rejected_handler_example",
        priority="critical",
    ),
]


def _dynamic_handler_documents(store: Any) -> list[dict[str, Any]]:
    try:
        handlers = store.latest_behavior(since_version=0).get("handlers", [])
    except Exception:
        return []
    documents = []
    for handler in handlers:
        command = handler.get("command", "")
        argv_match = handler.get("argv_match", {})
        patterns = argv_match.get("patterns", [])
        if not isinstance(patterns, list):
            patterns = []
        documents.append(
            _doc(
                f"Live accepted handler: {command} {patterns}",
                (
                    "This handler has already passed validation and is active "
                    "in the shared behavior cache. Prefer its structure for "
                    "similar commands, but keep argv_match aligned with the "
                    "new triggering argv.\n"
                    f"{json.dumps(handler, sort_keys=True)}"
                ),
                "live_accepted_handler",
                command=command,
                argv_pattern=[str(item) for item in patterns],
                source_type="live-handler-cache",
                priority="high",
            )
        )
    return documents


def seed_default_rag() -> int:
    store = make_store()
    embedding_client = EmbeddingClient()
    source_id = store.add_rag_source(
        _SOURCE_NAME,
        _SOURCE_TYPE,
        _SOURCE_VERSION,
        _SOURCE_URI,
    )
    documents = [*_DEFAULT_RAG_DOCUMENTS, *_dynamic_handler_documents(store)]
    count = 0
    for document in documents:
        embedding = embedding_client.embed(document["text"])
        store.add_rag_chunk(
            source_id,
            document["text"],
            embedding,
            document["metadata"],
        )
        count += 1
    return count


def main() -> None:
    count = seed_default_rag()
    print(f"ensured {count} adaptive RAG chunks")  # noqa: T201


if __name__ == "__main__":
    main()
