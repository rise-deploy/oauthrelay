#!/usr/bin/env python3
"""Validate generated CRDs, the provider and the Kubernetes transient store in a disposable Kind cluster.

The last phase deploys a real Dex with Kubernetes storage and runs the Dex AuthCode mapping against it.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DEX_MANIFEST = "tests/kubernetes/dex.yaml"
DEX_PORT = 15556
# Matches `issuer:` in the manifest's Dex config.
DEX_ISSUER = f"http://127.0.0.1:{DEX_PORT}/dex"


def run(*args, timeout=120, **kwargs):
    return subprocess.run(args, cwd=ROOT, timeout=timeout, check=True, **kwargs)


def dex_image():
    return re.search(r"image: (ghcr\.io/dexidp/dex:\S+)", (ROOT / DEX_MANIFEST).read_text()).group(1)


def start_port_forward(kubectl, log):
    return subprocess.Popen(
        [*kubectl, "port-forward", "-n", "dex", "service/dex", f"{DEX_PORT}:5556"],
        cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)


def wait_for_dex(kubectl, log, timeout=180):
    """Waits until Dex answers on the forwarded port, restarting the forward if it died."""
    url = f"{DEX_ISSUER}/.well-known/openid-configuration"
    forward = start_port_forward(kubectl, log)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if forward.poll() is not None:
            forward = start_port_forward(kubectl, log)
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return forward
        except OSError:
            pass
        time.sleep(1)
    forward.terminate()
    raise RuntimeError(f"Dex did not answer at {url} within {timeout}s")


def run_dex_phase(name, kubectl, kubectl_watch, log, env):
    image = dex_image()
    run("kind", "load", "docker-image", image, "--name", name, timeout=300)
    # Dex installs its own CRDs: drop the fixture the other tests used, and its objects.
    run(*kubectl, "delete", "crd", "authcodes.dex.coreos.com", "--ignore-not-found", "--timeout=60s", timeout=90)
    run(*kubectl, "delete", "namespace", "dex", "--ignore-not-found", "--timeout=120s", timeout=150)
    run(*kubectl, "apply", "-f", DEX_MANIFEST)
    run(*kubectl_watch, "wait", "--for=condition=Available", "--timeout=180s", "-n", "dex", "deployment/dex", timeout=200)
    forward = wait_for_dex(kubectl, log)
    try:
        run("cargo", "test", "--locked", "-p", "oauthrelay-store-kubernetes", "--test", "dex", "--",
            "--ignored", "--nocapture", "--test-threads=1", timeout=900,
            env=dict(env, OAUTHRELAY_DEX_TEST_ISSUER=DEX_ISSUER))
    finally:
        forward.terminate()
        forward.wait()


def main():
    with tempfile.TemporaryDirectory(prefix="oauthrelay-kubernetes-") as directory:
        config = str(Path(directory) / "kubeconfig")
        name = f"oauthrelay-test-{os.getpid()}"
        # Fetched while the cluster is created.
        pull = subprocess.Popen(["docker", "pull", dex_image()], cwd=ROOT)
        try:
            run("kind", "create", "cluster", "--name", name, "--image", "kindest/node:v1.35.0",
                "--kubeconfig", config, "--wait", "120s", timeout=300)
            kubectl = ["kubectl", "--kubeconfig", config, "--request-timeout=30s"]
            # `wait` and `rollout` watch, which the request timeout would cut short.
            kubectl_watch = ["kubectl", "--kubeconfig", config]
            run(*kubectl, "apply", "--server-side", "-f", "deploy/oauthrelay.crds.yaml",
                "-f", "tests/kubernetes/dex-authcodes.crd.yaml")
            run(*kubectl, "wait", "--for=condition=Established", "--timeout=60s",
                "crd/upstreams.oauthrelay.dev", "crd/relays.oauthrelay.dev",
                "crd/transientrecords.oauthrelay.dev", "crd/authcodes.dex.coreos.com")
            env = dict(os.environ, RUSTC_WRAPPER="", OAUTHRELAY_KUBERNETES_TEST_KUBECONFIG=config)
            run("cargo", "test", "--locked", "-p", "oauthrelay-provider-kubernetes",
                "--test", "kubernetes", "--", "--ignored", "--nocapture", timeout=600, env=env)
            # One test at a time: the sweeper tests would otherwise delete each other's records.
            run("cargo", "test", "--locked", "-p", "oauthrelay-store-kubernetes",
                "--test", "kubernetes", "--", "--ignored", "--nocapture", "--test-threads=1",
                timeout=600, env=env)
            # Built before Dex starts, so that compiling does not eat into the wait for Dex's
            # garbage collector, which runs every five minutes from its start.
            run("cargo", "test", "--locked", "-p", "oauthrelay-store-kubernetes",
                "--test", "dex", "--no-run", timeout=600, env=env)
            if pull.wait(timeout=300) != 0:
                raise RuntimeError("docker pull of the Dex image failed")
            with open(Path(directory) / "port-forward.log", "w+") as log:
                try:
                    run_dex_phase(name, kubectl, kubectl_watch, log, env)
                except BaseException:
                    # Whatever failed, Dex's own account of it is the first thing to look at.
                    subprocess.run([*kubectl, "get", "pods", "-n", "dex", "-o", "wide"], cwd=ROOT)
                    subprocess.run([*kubectl, "logs", "-n", "dex", "deployment/dex", "--tail=200"], cwd=ROOT)
                    subprocess.run([*kubectl, "describe", "pods", "-n", "dex"], cwd=ROOT)
                    log.seek(0)
                    print("--- kubectl port-forward ---\n" + log.read())
                    raise
        finally:
            if pull.poll() is None:
                pull.kill()
            run("kind", "delete", "cluster", "--name", name, timeout=120)


if __name__ == "__main__":
    main()
