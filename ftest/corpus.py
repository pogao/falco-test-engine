"""Ordinary activity on a Kubernetes node, generated from activity templates crossed with workloads.

Every event is benign by construction: an app container starting, its entrypoint script running
helpers, exec health checks, config and library reads, log and data writes, DNS and kube-API
connects, and the host daemons that run the node. The noise check runs each analyzed rule over
these events. A correct rule fires on few or none of them; an inverted rule fires on most of them.

Events set the fields that libsinsp always has for a syscall event, so a negated check over a field
behaves as it would in production instead of being true because the field is missing.
"""

from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from ftest.fixtures import derive
from ftest.suite import Case, SuiteError, parse_event

ID_PREFIX = "ordinary::"


@dataclass(frozen=True)
class Proc:
    """A process as Falco reports it. `argv` is argv[0] then the arguments."""

    exepath: str
    argv: str
    comm: str | None = None

    @property
    def exe(self) -> str:
        return self.argv.split(" ", 1)[0]

    @property
    def args(self) -> str:
        parts = self.argv.split(" ", 1)
        return parts[1] if len(parts) == 2 else ""

    @property
    def name(self) -> str:
        return self.comm or posixpath.basename(self.exe)[:15]

    @property
    def cmdline(self) -> str:
        return f"{self.name} {self.args}".rstrip()


@dataclass(frozen=True)
class Dest:
    ip: str
    port: int
    proto: str
    name: str | None = None


@dataclass(frozen=True)
class Pod:
    namespace: str
    deployment: str
    container: str
    image: str
    tag: str
    ip: str
    privileged: bool = False
    replicas: int = 1
    replica: int = 0


@dataclass(frozen=True)
class Probe:
    """An exec probe: the kubelet has runc start `command` in the container, through `sh -c` or not."""

    command: Proc
    shell: bool
    dest: Dest | None = None


@dataclass(frozen=True)
class Workload:
    name: str
    main: Proc
    user: tuple[str, int]
    pod: Pod | None
    parents: tuple[Proc, ...]
    entrypoint: Proc | None = None
    helpers: tuple[Proc, ...] = ()
    probes: tuple[Probe, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    connects: tuple[Dest, ...] = ()


@dataclass(frozen=True)
class Activity:
    actor: Proc
    ancestors: tuple[Proc, ...]
    what: str
    fields: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Template:
    key: str
    events: Callable[[Workload], Iterator[Activity]]


SYSTEMD = Proc("/usr/lib/systemd/systemd", "/sbin/init", comm="systemd")
SHIM = Proc(
    "/usr/bin/containerd-shim-runc-v2",
    "/usr/bin/containerd-shim-runc-v2 -namespace k8s.io -address /run/containerd/containerd.sock",
)
RUNC = Proc(
    "/usr/bin/runc", "runc --root /run/containerd/runc/k8s.io exec --process /tmp/runc-process --detach"
)
IN_POD = (SHIM, SYSTEMD)
NODE_IP = "10.0.1.12"

KUBE_DNS = Dest("10.96.0.10", 53, "udp", "kube-dns.kube-system.svc.cluster.local")
KUBE_API = Dest("10.96.0.1", 443, "tcp", "kubernetes.default.svc.cluster.local")
EKS_API = Dest("10.0.0.10", 443, "tcp", "api.cluster.internal")
VPC_DNS = Dest("10.0.0.2", 53, "udp")
IMDS = Dest("169.254.169.254", 80, "tcp")
POSTGRES = Dest("10.96.14.20", 5432, "tcp", "postgres.data.svc.cluster.local")
REDIS = Dest("10.96.33.8", 6379, "tcp", "redis.data.svc.cluster.local")
PAYMENTS = Dest("10.96.20.5", 8080, "tcp", "payments-api.payments.svc.cluster.local")

GLIBC = ("/etc/ld.so.cache", "/lib/x86_64-linux-gnu/libc.so.6")
RESOLVER = ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf")
TLS = ("/etc/ssl/certs/ca-certificates.crt",)
SERVICE_ACCOUNT = (
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
)


def _sh(command: str, shell: str = "sh") -> Proc:
    return Proc(f"/bin/{shell}", f"{shell} -c {command}")


def _local(port: int) -> Dest:
    return Dest("127.0.0.1", port, "tcp")


CONTAINERS: tuple[Workload, ...] = (
    Workload(
        "nginx",
        Proc("/usr/sbin/nginx", "nginx -g daemon off;"),
        ("root", 0),
        Pod("web", "web", "nginx", "docker.io/library/nginx", "1.27.2", "10.244.1.14", replicas=3),
        IN_POD,
        entrypoint=Proc(
            "/docker-entrypoint.sh", "/docker-entrypoint.sh nginx -g daemon off;", "docker-entrypoi"
        ),
        helpers=(
            Proc("/usr/bin/find", "find /docker-entrypoint.d/ -mindepth 1 -maxdepth 1 -type f -print -quit"),
            Proc("/usr/bin/sort", "sort -V"),
            Proc("/usr/bin/envsubst", "envsubst $NGINX_HOST $NGINX_PORT"),
            Proc("/usr/bin/sed", "sed -i -E s,listen 80;,listen 8080;, /etc/nginx/conf.d/default.conf"),
        ),
        reads=(*GLIBC, "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf", "/etc/nginx/mime.types"),
        writes=("/var/cache/nginx/client_temp/0000000001",),
        connects=(KUBE_DNS, PAYMENTS),
    ),
    Workload(
        "payments-api",
        Proc("/app/payments-api", "/app/payments-api --config /etc/payments/config.yaml"),
        ("app", 10001),
        Pod(
            "payments",
            "payments-api",
            "api",
            "ghcr.io/acme/payments-api",
            "v2.14.0",
            "10.244.1.23",
            replicas=2,
        ),
        IN_POD,
        entrypoint=_sh(
            "envsubst < /etc/payments/config.tmpl > /etc/payments/config.yaml && exec /app/payments-api"
        ),
        helpers=(Proc("/usr/bin/envsubst", "envsubst"),),
        probes=(
            Probe(Proc("/usr/bin/wget", "wget -q -O- http://127.0.0.1:8080/healthz"), True, _local(8080)),
        ),
        reads=(*RESOLVER, *TLS, *SERVICE_ACCOUNT[:1], "/etc/payments/config.yaml"),
        connects=(
            KUBE_DNS,
            POSTGRES,
            REDIS,
            Dest("203.0.113.40", 443, "tcp", "api.payments-gateway.example"),
        ),
    ),
    Workload(
        "storefront",
        Proc("/usr/local/bin/node", "node server.js"),
        ("node", 1000),
        Pod(
            "shop",
            "storefront",
            "web",
            "docker.io/library/node",
            "22-bookworm-slim",
            "10.244.2.31",
            replicas=2,
        ),
        IN_POD,
        entrypoint=Proc(
            "/usr/local/bin/docker-entrypoint.sh",
            "/usr/local/bin/docker-entrypoint.sh node server.js",
            "docker-entrypoi",
        ),
        probes=(Probe(Proc("/usr/local/bin/node", "node /app/healthcheck.js"), True, _local(3000)),),
        reads=(
            *GLIBC,
            *RESOLVER,
            "/app/package.json",
            "/app/server.js",
            "/app/node_modules/express/index.js",
        ),
        connects=(KUBE_DNS, PAYMENTS, Dest("203.0.113.10", 443, "tcp", "cdn.shop.example")),
    ),
    Workload(
        "checkout-worker",
        Proc("/usr/local/bin/python3", "python3 -m celery -A checkout worker --loglevel=info"),
        ("app", 1000),
        Pod(
            "shop",
            "checkout-worker",
            "worker",
            "docker.io/library/python",
            "3.12-slim",
            "10.244.2.40",
            replicas=2,
        ),
        IN_POD,
        entrypoint=_sh("python3 manage.py migrate --noinput && exec celery -A checkout worker", "bash"),
        helpers=(Proc("/usr/local/bin/python3", "python3 manage.py migrate --noinput"),),
        probes=(
            Probe(Proc("/usr/local/bin/celery", "celery -A checkout inspect ping", "celery"), True, REDIS),
        ),
        reads=(
            *GLIBC,
            "/usr/local/lib/python3.12/encodings/__init__.py",
            "/usr/local/lib/python3.12/site-packages/celery/__init__.py",
            "/app/checkout/settings.py",
        ),
        writes=("/tmp/celerybeat-schedule",),
        connects=(KUBE_DNS, REDIS, POSTGRES),
    ),
    Workload(
        "postgres",
        Proc(
            "/usr/lib/postgresql/16/bin/postgres", "postgres -c config_file=/etc/postgresql/postgresql.conf"
        ),
        ("postgres", 999),
        Pod("data", "postgres", "postgres", "docker.io/library/postgres", "16.4", "10.244.3.8"),
        IN_POD,
        entrypoint=Proc(
            "/usr/local/bin/docker-entrypoint.sh",
            "/usr/local/bin/docker-entrypoint.sh postgres",
            "docker-entrypoi",
        ),
        helpers=(
            Proc("/usr/bin/id", "id -u"),
            Proc("/usr/bin/mkdir", "mkdir -p /var/lib/postgresql/data"),
            Proc("/usr/bin/find", "find /var/lib/postgresql/data -mindepth 1 -maxdepth 0"),
        ),
        probes=(
            Probe(
                Proc("/usr/bin/pg_isready", "pg_isready -U postgres -h 127.0.0.1 -p 5432"),
                False,
                _local(5432),
            ),
        ),
        reads=(
            *GLIBC,
            "/etc/postgresql/postgresql.conf",
            "/var/lib/postgresql/data/pg_hba.conf",
            "/usr/share/postgresql/16/timezonesets/Default",
        ),
        writes=(
            "/var/lib/postgresql/data/pg_wal/000000010000000000000001",
            "/var/lib/postgresql/data/base/16384/2619",
        ),
    ),
    Workload(
        "redis",
        Proc("/usr/local/bin/redis-server", "redis-server *:6379"),
        ("redis", 999),
        Pod("data", "redis", "redis", "docker.io/library/redis", "7.4", "10.244.3.12"),
        IN_POD,
        probes=(Probe(Proc("/usr/local/bin/redis-cli", "redis-cli ping"), True, _local(6379)),),
        reads=(*GLIBC, "/usr/local/etc/redis/redis.conf"),
        writes=("/data/temp-27.rdb", "/data/appendonlydir/appendonly.aof.1.incr.aof"),
    ),
    Workload(
        "backup",
        Proc(
            "/bin/sh",
            "sh -c pg_dump -h postgres.data.svc.cluster.local -U backup shop | gzip > /backup/shop.sql.gz",
        ),
        ("backup", 1000),
        Pod("data", "backup-28813200", "backup", "docker.io/library/postgres", "16.4", "10.244.3.30"),
        IN_POD,
        helpers=(
            Proc("/usr/bin/pg_dump", "pg_dump -h postgres.data.svc.cluster.local -U backup shop"),
            Proc("/usr/bin/gzip", "gzip"),
        ),
        writes=("/backup/shop.sql.gz",),
        connects=(KUBE_DNS, POSTGRES),
    ),
    Workload(
        "prometheus",
        Proc(
            "/bin/prometheus",
            "/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus",
        ),
        ("nobody", 65534),
        Pod(
            "monitoring", "prometheus", "prometheus", "quay.io/prometheus/prometheus", "v2.54.1", "10.244.4.5"
        ),
        IN_POD,
        reads=(*RESOLVER, *SERVICE_ACCOUNT, "/etc/prometheus/prometheus.yml"),
        writes=("/prometheus/wal/00000003", "/prometheus/chunks_head/000001"),
        connects=(KUBE_DNS, KUBE_API, Dest(NODE_IP, 9100, "tcp"), Dest("10.244.1.23", 8080, "tcp")),
    ),
    Workload(
        "node-exporter",
        Proc("/bin/node_exporter", "/bin/node_exporter --path.rootfs=/host --path.procfs=/host/proc"),
        ("nobody", 65534),
        Pod(
            "monitoring",
            "node-exporter",
            "node-exporter",
            "quay.io/prometheus/node-exporter",
            "v1.8.2",
            NODE_IP,
        ),
        IN_POD,
        reads=("/host/proc/stat", "/host/proc/meminfo", "/host/sys/class/net/eth0/statistics/rx_bytes"),
    ),
    Workload(
        "coredns",
        Proc("/coredns", "/coredns -conf /etc/coredns/Corefile"),
        ("nonroot", 65532),
        Pod("kube-system", "coredns", "coredns", "registry.k8s.io/coredns/coredns", "v1.11.3", "10.244.0.3"),
        IN_POD,
        reads=(*SERVICE_ACCOUNT, "/etc/coredns/Corefile"),
        connects=(KUBE_API, VPC_DNS),
    ),
    Workload(
        "kube-proxy",
        Proc("/usr/local/bin/kube-proxy", "kube-proxy --config=/var/lib/kube-proxy/config.conf"),
        ("root", 0),
        Pod(
            "kube-system", "kube-proxy", "kube-proxy", "registry.k8s.io/kube-proxy", "v1.31.1", NODE_IP, True
        ),
        IN_POD,
        helpers=(
            Proc("/usr/sbin/iptables-restore", "iptables-restore -w 5 -W 100000 --noflush --counters"),
            Proc("/usr/sbin/iptables", "iptables -w 5 -W 100000 -N KUBE-KUBELET-CANARY -t mangle"),
        ),
        reads=("/var/lib/kube-proxy/config.conf", "/var/lib/kube-proxy/kubeconfig.conf"),
        connects=(EKS_API,),
    ),
    Workload(
        "aws-node",
        Proc("/app/aws-k8s-agent", "/app/aws-k8s-agent"),
        ("root", 0),
        Pod("kube-system", "aws-node", "aws-node", "public.ecr.aws/eks/aws-node", "v1.18.5", NODE_IP, True),
        IN_POD,
        probes=(
            Probe(
                Proc("/app/grpc-health-probe", "/app/grpc-health-probe -addr=:50051 -connect-timeout=5s"),
                False,
                _local(50051),
            ),
        ),
        reads=(*SERVICE_ACCOUNT, "/host/etc/cni/net.d/10-aws.conflist"),
        connects=(IMDS, KUBE_API),
    ),
    Workload(
        "fluent-bit",
        Proc("/fluent-bit/bin/fluent-bit", "/fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluent-bit.conf"),
        ("root", 0),
        Pod(
            "kube-system",
            "fluent-bit",
            "fluent-bit",
            "cr.fluentbit.io/fluent/fluent-bit",
            "3.1.9",
            "10.244.0.9",
        ),
        IN_POD,
        reads=(
            *GLIBC,
            "/fluent-bit/etc/fluent-bit.conf",
            "/var/log/containers/payments-api-7f9c6d5b8-qx2lm_payments_api-3f1a.log",
            "/var/log/containers/web-6d4cf56db6-x7k2p_web_nginx-9b2e.log",
        ),
        writes=("/var/fluent-bit/state/flb_kube.db",),
        connects=(KUBE_DNS, KUBE_API, Dest("203.0.113.80", 443, "tcp", "logs.observability.example")),
    ),
    Workload(
        "cert-manager-cainjector",
        Proc("/app/cmd/cainjector/cainjector", "/app/cmd/cainjector/cainjector --v=2"),
        ("nonroot", 65532),
        Pod(
            "cert-manager",
            "cert-manager-cainjector",
            "cert-manager-cainjector",
            "quay.io/jetstack/cert-manager-cainjector",
            "v1.15.3",
            "10.244.4.17",
        ),
        IN_POD,
        reads=SERVICE_ACCOUNT,
        connects=(KUBE_API,),
    ),
    Workload(
        "orders",
        Proc("/opt/java/openjdk/bin/java", "java -XX:MaxRAMPercentage=75 -jar /app/orders.jar"),
        ("app", 1000),
        Pod(
            "shop",
            "orders",
            "orders",
            "docker.io/library/eclipse-temurin",
            "21-jre",
            "10.244.2.52",
            replicas=2,
        ),
        IN_POD,
        probes=(
            Probe(
                Proc("/usr/bin/curl", "curl -fsS http://localhost:8081/actuator/health"), True, _local(8081)
            ),
        ),
        reads=(*GLIBC, *RESOLVER, *TLS, "/opt/java/openjdk/lib/modules", "/app/config/application.yaml"),
        writes=("/tmp/hsperfdata_app/1",),
        connects=(KUBE_DNS, POSTGRES, Dest("10.96.40.2", 9092, "tcp", "kafka.data.svc.cluster.local")),
    ),
    Workload(
        "istio-proxy",
        Proc(
            "/usr/local/bin/pilot-agent",
            "/usr/local/bin/pilot-agent proxy sidecar --domain payments.svc.cluster.local",
        ),
        ("istio-proxy", 1337),
        Pod(
            "payments",
            "payments-api",
            "istio-proxy",
            "docker.io/istio/proxyv2",
            "1.23.2",
            "10.244.1.23",
            replicas=2,
        ),
        IN_POD,
        helpers=(
            Proc(
                "/usr/local/bin/envoy",
                "/usr/local/bin/envoy -c etc/istio/proxy/envoy-rev.json --drain-time-s 45",
            ),
        ),
        reads=(
            *SERVICE_ACCOUNT[:1],
            "/etc/istio/proxy/envoy-rev.json",
            "/var/run/secrets/istio/root-cert.pem",
        ),
        connects=(KUBE_DNS, Dest("10.96.5.5", 15012, "tcp", "istiod.istio-system.svc")),
    ),
)

KUBELET = Proc(
    "/usr/bin/kubelet",
    "/usr/bin/kubelet --config /etc/kubernetes/kubelet/config.json --kubeconfig /var/lib/kubelet/kubeconfig",
)
CONTAINERD = Proc("/usr/bin/containerd", "/usr/bin/containerd")
SSM_AGENT = Proc("/usr/bin/amazon-ssm-agent", "/usr/bin/amazon-ssm-agent")
SSM_WORKER = Proc("/usr/bin/ssm-agent-worker", "/usr/bin/ssm-agent-worker")

HOST: tuple[Workload, ...] = (
    Workload(
        "kubelet",
        KUBELET,
        ("root", 0),
        None,
        (SYSTEMD,),
        helpers=(
            Proc(
                "/usr/bin/mount",
                "mount -t tmpfs tmpfs /var/lib/kubelet/pods/5e3c/volumes/kubernetes.io~projected/kube-api-access-8x2lq",
            ),
            Proc(
                "/usr/bin/umount",
                "umount /var/lib/kubelet/pods/1b7d/volumes/kubernetes.io~projected/kube-api-access-c9f4z",
            ),
            Proc("/usr/bin/nice", "nice -n 19 du -x -s -B 1 /var/lib/kubelet/pods/5e3c/volumes"),
        ),
        reads=(
            "/etc/kubernetes/kubelet/config.json",
            "/var/lib/kubelet/kubeconfig",
            "/var/lib/kubelet/pki/kubelet-client-current.pem",
            "/proc/1/cgroup",
        ),
        writes=("/var/lib/kubelet/cpu_manager_state", "/var/lib/kubelet/pods/5e3c/etc-hosts"),
        connects=(EKS_API, Dest("10.244.1.14", 8080, "tcp"), Dest("10.244.4.5", 9090, "tcp"), VPC_DNS),
    ),
    Workload(
        "containerd",
        CONTAINERD,
        ("root", 0),
        None,
        (SYSTEMD,),
        helpers=(
            SHIM,
            Proc(
                "/usr/bin/runc",
                "runc --root /run/containerd/runc/k8s.io create --bundle /run/containerd/io.containerd.runtime.v2.task/k8s.io/3f1a",
            ),
        ),
        reads=("/etc/containerd/config.toml", "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"),
        writes=(
            "/var/log/pods/web_web-6d4cf56db6-x7k2p_5e3c/nginx/0.log",
            "/var/lib/containerd/io.containerd.content.v1.content/ingest/8a1f/data",
        ),
        connects=(
            Dest("198.51.100.20", 443, "tcp", "ghcr.io"),
            Dest("198.51.100.30", 443, "tcp", "registry.k8s.io"),
        ),
    ),
    Workload(
        "containerd-shim",
        SHIM,
        ("root", 0),
        None,
        (SYSTEMD,),
        helpers=(RUNC,),
        reads=("/run/containerd/io.containerd.runtime.v2.task/k8s.io/3f1a/config.json",),
    ),
    Workload(
        "systemd",
        SYSTEMD,
        ("root", 0),
        None,
        (),
        helpers=(Proc("/usr/bin/systemd-tmpfiles", "/usr/bin/systemd-tmpfiles --clean"),),
        reads=("/etc/systemd/system.conf", "/proc/1/mountinfo"),
    ),
    Workload(
        "systemd-journald",
        Proc("/usr/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald"),
        ("root", 0),
        None,
        (SYSTEMD,),
        reads=("/etc/systemd/journald.conf", "/proc/3021/cmdline"),
        writes=("/var/log/journal/ec2a8f0e9c4b4f0b/system.journal",),
    ),
    Workload(
        "chronyd",
        Proc("/usr/sbin/chronyd", "/usr/sbin/chronyd -F 2"),
        ("chrony", 992),
        None,
        (SYSTEMD,),
        reads=("/etc/chrony.conf",),
        writes=("/var/lib/chrony/drift",),
        connects=(Dest("169.254.169.123", 123, "udp"),),
    ),
    Workload(
        "logrotate",
        Proc("/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf"),
        ("root", 0),
        None,
        (SYSTEMD,),
        reads=("/etc/logrotate.conf", "/etc/logrotate.d/rsyslog"),
        writes=("/var/lib/logrotate/logrotate.status",),
    ),
    Workload(
        "amazon-ssm-agent",
        SSM_AGENT,
        ("root", 0),
        None,
        (SYSTEMD,),
        helpers=(SSM_WORKER,),
        reads=("/etc/amazon/ssm/amazon-ssm-agent.json",),
        connects=(IMDS, Dest("203.0.113.50", 443, "tcp", "ssm.us-east-1.amazonaws.com")),
    ),
    Workload(
        "security patching",
        _sh("dnf -y upgrade --security"),
        ("root", 0),
        None,
        (SSM_WORKER, SSM_AGENT, SYSTEMD),
        helpers=(Proc("/usr/bin/dnf", "dnf -y upgrade --security"), Proc("/usr/bin/rpm", "rpm -q kernel")),
        reads=("/etc/dnf/dnf.conf", "/var/lib/rpm/rpmdb.sqlite"),
        connects=(Dest("198.51.100.60", 443, "tcp", "cdn.amazonlinux.com"),),
    ),
)


def _replicas(w: Workload) -> Iterator[Workload]:
    """Each replica is its own pod: same activity, its own container id, pod name, and pod IP."""
    if w.pod is None or w.pod.replicas == 1:
        yield w
        return
    head, _, last = w.pod.ip.rpartition(".")
    for r in range(w.pod.replicas):
        pod = replace(w.pod, ip=f"{head}.{int(last) + r}", replica=r)
        yield replace(w, name=f"{w.name}#{r + 1}", pod=pod)


WORKLOADS: tuple[Workload, ...] = tuple(r for w in CONTAINERS for r in _replicas(w)) + HOST


def _start(w: Workload) -> Iterator[Activity]:
    """The runtime starts the container's entrypoint, which execs the app; systemd starts a daemon."""
    for proc in (w.entrypoint, w.main) if w.entrypoint else (w.main,):
        yield Activity(proc, w.parents, f"starts {proc.cmdline}", _exec())


def _helpers(w: Workload) -> Iterator[Activity]:
    """The entrypoint script, or the daemon itself, runs short-lived helpers."""
    lineage = (w.entrypoint or w.main, *w.parents)
    for helper in w.helpers:
        yield Activity(helper, lineage, f"runs {helper.cmdline}", _exec())


def _probes(w: Workload) -> Iterator[Activity]:
    """Exec probes run with no terminal, started by runc inside the container."""
    for probe in w.probes:
        lineage = (RUNC, *w.parents)
        if probe.shell:
            shell = _sh(probe.command.cmdline)
            yield Activity(shell, lineage, f"health check {shell.cmdline}", _exec())
            lineage = (shell, *lineage)
        yield Activity(probe.command, lineage, f"health check {probe.command.cmdline}", _exec())
        if probe.dest is not None:
            yield Activity(
                probe.command,
                lineage,
                f"health check connects to {probe.dest.ip}:{probe.dest.port}",
                _connect(w, probe.dest, 0),
            )


def _reads(w: Workload) -> Iterator[Activity]:
    for i, path in enumerate(w.reads):
        yield Activity(
            w.main,
            w.parents,
            f"reads {path}",
            _open(path, i, read=True, write=False, flags="O_RDONLY|O_CLOEXEC"),
        )


def _writes(w: Workload) -> Iterator[Activity]:
    for i, path in enumerate(w.writes):
        flags = (
            "O_RDWR|O_CREAT|O_CLOEXEC"
            if "/data/" in path or path.endswith(".db")
            else "O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC"
        )
        yield Activity(
            w.main,
            w.parents,
            f"writes {path}",
            _open(path, len(w.reads) + i, read="O_RDWR" in flags, write=True, flags=flags),
        )


def _connects(w: Workload) -> Iterator[Activity]:
    for i, dest in enumerate(w.connects):
        where = dest.name or f"{dest.ip}:{dest.port}"
        yield Activity(w.main, w.parents, f"connects to {where}", _connect(w, dest, i + 1))


TEMPLATES: tuple[Template, ...] = (
    Template("start", _start),
    Template("helper", _helpers),
    Template("probe", _probes),
    Template("read", _reads),
    Template("write", _writes),
    Template("connect", _connects),
)


def _exec() -> dict[str, tuple[str, ...]]:
    return {
        "evt.type": ("execve",),
        "proc.is_exe_upper_layer": ("false",),
        "proc.is_exe_from_memfd": ("false",),
    }


def _open(path: str, index: int, read: bool, write: bool, flags: str) -> dict[str, tuple[str, ...]]:
    fd = str(3 + index % 20)
    return {
        "evt.type": ("openat",),
        "evt.is_open_read": (_bool(read),),
        "evt.is_open_write": (_bool(write),),
        "evt.arg.flags": (flags,),
        "evt.rawres": (fd,),
        "fd.num": (fd,),
        "fd.typechar": ("f",),
        "fd.type": ("file",),
        "fd.name": (path,),
        "fd.nameraw": (path,),
    }


def _connect(w: Workload, dest: Dest, index: int) -> dict[str, tuple[str, ...]]:
    local = dest.ip == "127.0.0.1"
    client_ip = "127.0.0.1" if local else (w.pod.ip if w.pod else NODE_IP)
    client_port = str(32768 + int(_digest(w.name, str(index), dest.ip), 16) % 28000)
    fields = {
        "evt.type": ("connect",),
        "evt.rawres": ("0",),
        "fd.num": (str(5 + index % 20),),
        "fd.typechar": ("4",),
        "fd.type": ("ipv4",),
        "fd.l4proto": (dest.proto,),
        "fd.cip": (client_ip,),
        "fd.cport": (client_port,),
        "fd.sip": (dest.ip,),
        "fd.sport": (str(dest.port),),
        "fd.name": (f"{client_ip}:{client_port}->{dest.ip}:{dest.port}",),
    }
    if dest.name:
        fields["fd.sip.name"] = (dest.name,)
    return fields


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _digest(*parts: str) -> str:
    return hashlib.sha256("/".join(parts).encode()).hexdigest()


def _context(w: Workload) -> dict[str, tuple[str, ...]]:
    if w.pod is None:
        return {"container.id": ("host",), "container.name": ("host",)}
    pod = w.pod
    replica_set = _digest(pod.namespace, pod.deployment)[:10]
    digest = _digest(pod.namespace, pod.deployment, str(pod.replica))
    return {
        "container.id": (_digest(pod.namespace, pod.deployment, pod.container, str(pod.replica))[:12],),
        "container.name": (pod.container,),
        "container.image": (f"{pod.image}:{pod.tag}",),
        "container.image.repository": (pod.image,),
        "container.image.tag": (pod.tag,),
        "container.privileged": (_bool(pod.privileged),),
        "k8s.ns.name": (pod.namespace,),
        "k8s.pod.name": (f"{pod.deployment}-{replica_set}-{digest[:5]}",),
    }


def _process(actor: Proc, ancestors: Sequence[Proc], user: tuple[str, int]) -> dict[str, tuple[str, ...]]:
    fields = {
        "proc.name": (actor.name,),
        "proc.exe": (actor.exe,),
        "proc.exepath": (actor.exepath,),
        "proc.cmdline": (actor.cmdline,),
        "proc.args": (actor.args,),
        "proc.tty": ("0",),
        "user.name": (user[0],),
        "user.uid": (str(user[1]),),
    }
    if ancestors:
        fields["proc.aname"] = tuple(a.name for a in ancestors)
        fields["proc.aexe"] = tuple(a.exe for a in ancestors)
        fields["proc.aexepath"] = tuple(a.exepath for a in ancestors)
        fields["proc.acmdline"] = tuple(a.cmdline for a in ancestors)
    return fields


def builtin() -> tuple[Case, ...]:
    """The built-in corpus. A pure function of the tables above, so every run sees the same events."""
    events = []
    for template in TEMPLATES:
        for w in WORKLOADS:
            for n, activity in enumerate(template.events(w)):
                given = {
                    "evt.num": (str(len(events) + 1),),
                    **_process(activity.actor, activity.ancestors, w.user),
                    **_context(w),
                    **activity.fields,
                }
                where = "host" if w.pod is None else f"container {w.pod.namespace}/{w.pod.deployment}"
                events.append(
                    Case(
                        f"{ID_PREFIX}{template.key}/{w.name}/{n}",
                        f"{w.name} ({where}) {activity.what}",
                        derive(given),
                        (),
                        given,
                    )
                )
    return tuple(events)


def load_corpus(paths: Iterable[Path], root: Path) -> tuple[Case, ...]:
    """User corpus files: each is a YAML list of events in the suite event format."""
    events = []
    for path in paths:
        display = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        try:
            raw = yaml.safe_load(path.read_text())
        except OSError as e:
            raise SuiteError(f"cannot read corpus file {display}: {e.strerror}") from e
        except yaml.YAMLError as e:
            raise SuiteError(f"{display}: invalid YAML: {e}") from e
        if not isinstance(raw, list) or not raw:
            raise SuiteError(f"{display}: a corpus file is a non-empty YAML list of events")
        for i, item in enumerate(raw, 1):
            given = parse_event(item, f"{display}: event {i}")
            if len(given.get("evt.type", ())) != 1:
                raise SuiteError(f"{display}: event {i} needs exactly one evt.type")
            events.append(Case(f"{ID_PREFIX}{display}#{i}", f"{display} event {i}", derive(given), (), given))
    return tuple(events)


def values_by_field(events: Iterable[Case]) -> dict[str, tuple[str, ...]]:
    """Distinct values of each field, in corpus order: realistic replacements for generated cases."""
    seen: dict[str, dict[str, None]] = {}
    for event in events:
        for key, values in event.event.items():
            seen.setdefault(key, {}).update(dict.fromkeys(values))
    return {key: tuple(values) for key, values in seen.items()}
